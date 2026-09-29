use std::sync::Arc;

use domain::identity::testing::{InMemoryAccounts, InMemoryRemoteActors, account, remote_actor};
use domain::identity::{Account, ActorUri, RemoteActor};
use domain::messaging::testing::{
    InMemoryMessaging, MessageNotice, Outbound, RecordingMessageFederation,
    RecordingMessageNotifier,
};
use domain::messaging::{ConversationKind, GroupSnapshot, Member, MessageEvent, Role};

use super::*;

pub(crate) struct Group {
    pub alice: Account,
    pub bob: Account,
    pub eve: Account,
    pub carol: RemoteActor,
    pub id: ConversationId,
    pub snapshot: GroupSnapshot,
    pub store: Arc<InMemoryMessaging>,
    pub notifier: Arc<RecordingMessageNotifier>,
    pub federation: Arc<RecordingMessageFederation>,
    pub accounts: Arc<InMemoryAccounts>,
    pub remote_actors: Arc<InMemoryRemoteActors>,
}

/// "crew": alice (admin) and bob here, carol on another instance, and dave, whose instance this
/// one has never heard of. Eve is local but not in it.
pub(crate) async fn crew() -> Group {
    let (alice, bob, eve) = (account("alice"), account("bob"), account("eve"));
    let carol = remote_actor("carol_k2m9x@idp.carol.test");
    let dave = ActorUri::parse("https://idp.dave.test/users/dave_k2m9x").unwrap();
    let member = |actor_uri: &ActorUri, role| Member {
        actor_uri: actor_uri.clone(),
        role,
    };
    let snapshot = GroupSnapshot {
        name: Some("crew".to_owned()),
        members: vec![
            member(&alice.actor_uri, Role::Admin),
            member(&bob.actor_uri, Role::Member),
            member(&carol.actor_uri, Role::Member),
            member(&dave, Role::Member),
        ],
    };
    let store = Arc::new(InMemoryMessaging::default());
    let id = ConversationId::generate();
    store.mirror_group(id, &snapshot).await.unwrap();
    Group {
        accounts: Arc::new(InMemoryAccounts::with([
            alice.clone(),
            bob.clone(),
            eve.clone(),
        ])),
        remote_actors: Arc::new(InMemoryRemoteActors::with([carol.clone()])),
        alice,
        bob,
        eve,
        carol,
        id,
        snapshot,
        store,
        notifier: Arc::new(RecordingMessageNotifier::default()),
        federation: Arc::new(RecordingMessageFederation::default()),
    }
}

fn send(g: &Group) -> SendGroupMessage {
    SendGroupMessage::new(
        2,
        g.accounts.clone(),
        g.remote_actors.clone(),
        g.store.clone(),
        g.store.clone(),
        g.notifier.clone(),
        g.federation.clone(),
    )
}

fn post(g: &Group) -> GroupMessageCommand {
    GroupMessageCommand {
        conversation: g.id,
        ciphertext: MlsCiphertext::parse(vec![9; 16]).unwrap(),
        reply_to: None,
        attachments: Vec::new(),
    }
}

#[tokio::test]
async fn a_group_message_reaches_the_local_members_and_goes_out_to_the_remote_ones() {
    let g = crew().await;

    let posted = send(&g).execute(g.alice.id, post(&g)).await.unwrap();

    let m = &posted.message;
    assert_eq!((m.conversation, &m.sender), (g.id, &g.alice.actor_uri));
    let event = MessageEvent {
        message: m.clone(),
        kind: ConversationKind::Group,
        sender_address: g.alice.actor_uri.federated_address().unwrap().to_string(),
        sender_display_name: Some("alice".to_owned()),
        client_id: None,
    };
    assert_eq!(
        g.notifier.sent(),
        vec![
            MessageNotice::Message(g.bob.id, event.clone()),
            MessageNotice::Echo(g.alice.id, event),
        ]
    );
    assert_eq!(
        g.federation.sent(),
        vec![Outbound::Group {
            from: g.alice.actor_uri.clone(),
            to: vec![g.carol.actor_uri.clone()],
            message: m.id,
            reply_to: None,
            group: g.snapshot.clone(),
        }],
        "carol gets it with the roster; dave's instance is unknown here"
    );
}

#[tokio::test]
async fn a_group_reply_names_its_parent_to_the_remote_members() {
    let g = crew().await;
    let parent = send(&g).execute(g.bob.id, post(&g)).await.unwrap().message;

    send(&g)
        .execute(
            g.alice.id,
            GroupMessageCommand {
                reply_to: Some(parent.id),
                ..post(&g)
            },
        )
        .await
        .unwrap();

    let Some(Outbound::Group { reply_to, .. }) = g.federation.sent().pop() else {
        panic!("no group send");
    };
    assert_eq!(reply_to, Some(parent.activity_uri));
}

#[tokio::test]
async fn only_a_member_posts_to_a_group() {
    let g = crew().await;

    let refused = send(&g).execute(g.eve.id, post(&g)).await;

    assert!(
        matches!(refused, Err(MessagingError::ConversationNotFound)),
        "{:?}",
        refused.map(|p| p.message)
    );
    assert!(g.notifier.sent().is_empty());
    assert!(g.federation.sent().is_empty());
}

#[tokio::test]
async fn a_reply_to_an_unknown_message_is_refused() {
    let g = crew().await;

    let refused = send(&g)
        .execute(
            g.alice.id,
            GroupMessageCommand {
                reply_to: Some(MessageId::generate()),
                ..post(&g)
            },
        )
        .await;

    assert!(matches!(refused, Err(MessagingError::ParentNotFound)));
}

#[tokio::test]
async fn a_group_message_takes_no_more_attachments_than_a_dm() {
    let g = crew().await;

    let refused = send(&g)
        .execute(
            g.alice.id,
            GroupMessageCommand {
                attachments: vec![AttachmentId::generate(); 3],
                ..post(&g)
            },
        )
        .await;

    assert!(
        matches!(refused, Err(MessagingError::TooManyAttachments(2))),
        "{:?}",
        refused.map(|p| p.message)
    );
    assert!(g.notifier.sent().is_empty());
}

#[tokio::test]
async fn a_group_reply_to_a_message_of_another_conversation_is_refused() {
    let g = crew().await;
    let dm = g
        .store
        .open_dm(&g.alice.actor_uri, &g.bob.actor_uri, None)
        .await
        .unwrap();
    let elsewhere = g
        .store
        .record(&domain::messaging::testing::contract::new_message(
            dm,
            &g.bob.actor_uri,
        ))
        .await
        .unwrap();

    let refused = send(&g)
        .execute(
            g.alice.id,
            GroupMessageCommand {
                reply_to: Some(elsewhere.id),
                ..post(&g)
            },
        )
        .await;

    assert!(matches!(refused, Err(MessagingError::ParentNotFound)));
    assert!(g.notifier.sent().is_empty());
}
