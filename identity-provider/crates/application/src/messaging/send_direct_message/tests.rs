use std::sync::Arc;

use domain::identity::testing::{InMemoryAccounts, InMemoryRemoteActors, account, remote_actor};
use domain::identity::{Account, FederatedAddress, Handle, RemoteActor};
use domain::messaging::testing::{
    InMemoryMessaging, MessageNotice, RecordingMessageNotifier, Uploads,
};
use domain::messaging::{ConversationKind, DeliveryStatus, MessageEvent};
use domain::social::testing::{BLOCKED, KEPT_OUT_BY_THE_SETTING, StubReachability};

use super::*;

struct World {
    alice: Account,
    bob: Account,
    carol: RemoteActor,
    store: Arc<InMemoryMessaging>,
    notifier: Arc<RecordingMessageNotifier>,
    reach: Arc<StubReachability>,
    send: SendDirectMessage,
}

fn world() -> World {
    let (alice, bob) = (account("alice"), account("bob"));
    let carol = remote_actor("carol_k2m9x@idp.carol.test");
    let store = Arc::new(InMemoryMessaging::default());
    let notifier = Arc::new(RecordingMessageNotifier::default());
    let reach = Arc::new(StubReachability::default());
    let send = SendDirectMessage::new(
        InstanceOrigin::parse("http://localhost:8080").unwrap(),
        2,
        Arc::new(InMemoryAccounts::with([alice.clone(), bob.clone()])),
        Arc::new(InMemoryRemoteActors::with([carol.clone()])),
        store.clone(),
        store.clone(),
        reach.clone(),
        notifier.clone(),
    );
    World {
        alice,
        bob,
        carol,
        store,
        notifier,
        reach,
        send,
    }
}

fn to(recipient: Recipient) -> DirectMessageCommand {
    DirectMessageCommand {
        recipient,
        ciphertext: MlsCiphertext::parse(vec![7; 16]).unwrap(),
        reply_to: None,
        attachments: Vec::new(),
        pinned: None,
        client_id: Some("optimistic-1".to_owned()),
    }
}

fn local(account: &Account) -> Recipient {
    Recipient::Local(Handle::parse(&account.username).unwrap())
}

fn remote() -> Recipient {
    Recipient::Remote(FederatedAddress::parse("carol_k2m9x@idp.carol.test").unwrap())
}

fn event(w: &World, message: &Message, client_id: Option<&str>) -> MessageEvent {
    MessageEvent {
        message: message.clone(),
        kind: ConversationKind::Dm,
        sender_address: w.alice.actor_uri.federated_address().unwrap().to_string(),
        sender_display_name: Some("alice".to_owned()),
        client_id: client_id.map(str::to_owned),
    }
}

#[tokio::test]
async fn a_message_to_a_local_account_reaches_both_parties_in_their_dm() {
    let w = world();

    let sent = w.send.execute(w.alice.id, to(local(&w.bob))).await.unwrap();

    let dm = w
        .store
        .open_dm(&w.alice.actor_uri, &w.bob.actor_uri, None)
        .await
        .unwrap();
    let m = &sent.message;
    assert_eq!((m.conversation, &m.sender), (dm, &w.alice.actor_uri));
    assert_eq!(m.activity_uri, m.id.activity_uri(&w.alice.actor_uri));
    assert_eq!(
        Messages::find(&*w.store, m.id).await.unwrap().as_ref(),
        Some(m)
    );
    assert!(
        sent.delivery.is_none(),
        "a local message has nothing to deliver"
    );
    assert_eq!(sent.sender_display_name, "alice");
    assert_eq!(
        w.notifier.sent(),
        vec![
            MessageNotice::Message(w.bob.id, event(&w, m, None)),
            MessageNotice::Message(w.alice.id, event(&w, m, Some("optimistic-1"))),
        ]
    );
}

#[tokio::test]
async fn a_message_to_a_remote_account_is_echoed_to_its_sender_and_left_to_deliver() {
    let w = world();

    let sent = w.send.execute(w.alice.id, to(remote())).await.unwrap();

    let m = &sent.message;
    assert_eq!(m.delivery, DeliveryStatus::Pending);
    assert_eq!(
        sent.delivery,
        Some(DirectDelivery {
            from: w.alice.clone(),
            to: w.carol.clone(),
            message: m.clone(),
            reply_to: None,
        })
    );
    assert_eq!(
        w.notifier.sent(),
        vec![MessageNotice::Echo(
            w.alice.id,
            event(&w, m, Some("optimistic-1"))
        )]
    );
}

#[tokio::test]
async fn a_reply_names_its_parent_to_both_instances() {
    let w = world();
    let parent = w
        .send
        .execute(w.alice.id, to(remote()))
        .await
        .unwrap()
        .message;

    let reply = w
        .send
        .execute(
            w.alice.id,
            DirectMessageCommand {
                reply_to: Some(parent.id),
                ..to(remote())
            },
        )
        .await
        .unwrap();

    assert_eq!(reply.message.reply_to, Some(parent.id));
    assert_eq!(reply.delivery.unwrap().reply_to, Some(parent.activity_uri));
}

#[tokio::test]
async fn a_pinned_id_opens_a_new_dm_under_it() {
    let w = world();
    let pinned = ConversationId::generate();

    let sent = w
        .send
        .execute(
            w.alice.id,
            DirectMessageCommand {
                pinned: Some(pinned),
                ..to(local(&w.bob))
            },
        )
        .await
        .unwrap();

    assert_eq!(sent.message.conversation, pinned);
}

#[tokio::test]
async fn the_senders_uploads_travel_with_the_message() {
    let w = world();
    let file = w.store.upload(&w.alice.actor_uri).await;

    let sent = w
        .send
        .execute(
            w.alice.id,
            DirectMessageCommand {
                attachments: vec![file],
                ..to(local(&w.bob))
            },
        )
        .await
        .unwrap();

    assert_eq!(sent.message.attachments.len(), 1);
    assert_eq!(sent.message.attachments[0].id, file);
}

#[tokio::test]
async fn a_message_that_cannot_be_sent_is_refused_and_stores_nothing() {
    let w = world();
    let bobs_upload = w.store.upload(&w.bob.actor_uri).await;
    let cases = [
        (
            to(Recipient::Local(Handle::parse("nobody_t3st0").unwrap())),
            "RecipientNotFound",
        ),
        (
            to(Recipient::Remote(
                FederatedAddress::parse("nobody_k2m9x@idp.carol.test").unwrap(),
            )),
            "RecipientNotFound",
        ),
        (to(local(&w.alice)), "SelfMessage"),
        (
            DirectMessageCommand {
                reply_to: Some(MessageId::generate()),
                ..to(local(&w.bob))
            },
            "ParentNotFound",
        ),
        (
            DirectMessageCommand {
                attachments: vec![AttachmentId::generate(); 3],
                ..to(local(&w.bob))
            },
            "TooManyAttachments(2)",
        ),
        (
            DirectMessageCommand {
                attachments: vec![bobs_upload],
                ..to(local(&w.bob))
            },
            "AttachmentsUnavailable",
        ),
    ];

    for (command, expected) in cases {
        let refused = w.send.execute(w.alice.id, command).await;

        assert_eq!(
            refused.map(|_| ()).map_err(|e| format!("{e:?}")),
            Err(expected.to_owned())
        );
    }
    assert!(w.notifier.sent().is_empty());
}

#[tokio::test]
async fn a_reply_to_a_message_of_another_conversation_is_refused() {
    let w = world();
    let elsewhere = w
        .send
        .execute(w.alice.id, to(remote()))
        .await
        .unwrap()
        .message;
    let notices = w.notifier.sent().len();

    let refused = w
        .send
        .execute(
            w.alice.id,
            DirectMessageCommand {
                reply_to: Some(elsewhere.id),
                ..to(local(&w.bob))
            },
        )
        .await;

    assert!(
        matches!(refused, Err(MessagingError::ParentNotFound)),
        "{:?}",
        refused.map(|s| s.message)
    );
    assert_eq!(w.notifier.sent().len(), notices, "nothing announced");
}

impl World {
    async fn conversations_of(&self, account: &Account) -> usize {
        self.store
            .list_for(account.id, &account.actor_uri)
            .await
            .unwrap()
            .len()
    }
}

#[tokio::test]
async fn a_message_to_someone_the_sender_blocked_is_refused_and_stores_nothing() {
    let w = world();
    w.reach.set(w.alice.id, &w.bob.actor_uri, BLOCKED);
    w.reach.set(w.alice.id, &w.carol.actor_uri, BLOCKED);

    for recipient in [local(&w.bob), remote()] {
        let refused = w.send.execute(w.alice.id, to(recipient)).await;

        assert!(
            matches!(refused, Err(MessagingError::YouBlocked)),
            "{:?}",
            refused.map(|_| ())
        );
    }
    assert_eq!(w.conversations_of(&w.alice).await, 0);
    assert!(w.notifier.sent().is_empty());
}

/// Bob must not tell a block from Alice's setting: both are the same refusal, and leave no DM
/// for either of them to list.
#[tokio::test]
async fn a_local_recipient_who_cannot_be_reached_gets_nothing_whatever_the_cause() {
    let mut refusals = Vec::new();
    for kept_out in [BLOCKED, KEPT_OUT_BY_THE_SETTING] {
        let w = world();
        w.reach.set(w.bob.id, &w.alice.actor_uri, kept_out);

        let refused = w.send.execute(w.alice.id, to(local(&w.bob))).await;

        refusals.push(format!("{:?}", refused.map(|_| ())));
        assert_eq!(w.conversations_of(&w.alice).await, 0);
        assert_eq!(w.conversations_of(&w.bob).await, 0);
        assert!(w.notifier.sent().is_empty());
    }
    assert_eq!(refusals, vec!["Err(Undeliverable)"; 2]);
}

#[tokio::test]
async fn a_message_to_an_instance_that_does_not_answer_is_refused_and_stores_nothing() {
    let alice = account("alice");
    let store = Arc::new(InMemoryMessaging::default());
    let send = SendDirectMessage::new(
        InstanceOrigin::parse("http://localhost:8080").unwrap(),
        2,
        Arc::new(InMemoryAccounts::with([alice.clone()])),
        Arc::new(InMemoryRemoteActors::default().and_down("idp.down.test")),
        store.clone(),
        store.clone(),
        Arc::new(StubReachability::default()),
        Arc::new(RecordingMessageNotifier::default()),
    );

    let refused = send
        .execute(
            alice.id,
            to(Recipient::Remote(
                FederatedAddress::parse("dave_k2m9x@idp.down.test").unwrap(),
            )),
        )
        .await;

    assert!(
        matches!(refused, Err(MessagingError::PeerUnavailable(_))),
        "{:?}",
        refused.map(|_| ())
    );
    assert!(
        store
            .list_for(alice.id, &alice.actor_uri)
            .await
            .unwrap()
            .is_empty()
    );
}
