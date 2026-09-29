use std::sync::Arc;

use domain::identity::testing::{InMemoryAccounts, InMemoryRemoteActors, account, remote_actor};
use domain::identity::{Account, RemoteActor};
use domain::messaging::testing::{
    GroupNotice, InMemoryMessaging, MessageNotice, RecordingGroupNotifier, RecordingMessageNotifier,
};
use domain::messaging::{ConversationKind, Member, Message, MessageEvent, MessagingError, Role};
use domain::{AttachmentId, MessageId};

use super::*;

pub(crate) struct World {
    pub alice: Account,
    pub bob: Account,
    pub carol: RemoteActor,
    pub store: Arc<InMemoryMessaging>,
    pub notifier: Arc<RecordingMessageNotifier>,
    pub groups: Arc<RecordingGroupNotifier>,
    pub accounts: Arc<InMemoryAccounts>,
    pub remote_actors: Arc<InMemoryRemoteActors>,
}

/// Alice and Bob here; Carol, on another instance, writes to Alice.
pub(crate) fn world() -> World {
    let (alice, bob) = (account("alice"), account("bob"));
    let carol = remote_actor("carol_k2m9x@idp.carol.test");
    World {
        accounts: Arc::new(InMemoryAccounts::with([alice.clone(), bob.clone()])),
        remote_actors: Arc::new(InMemoryRemoteActors::with([carol.clone()])),
        alice,
        bob,
        carol,
        store: Arc::new(InMemoryMessaging::default()),
        notifier: Arc::new(RecordingMessageNotifier::default()),
        groups: Arc::new(RecordingGroupNotifier::default()),
    }
}

fn receive(w: &World) -> ReceiveMessage {
    ReceiveMessage::new(
        AttachmentLimits {
            max_files: 5,
            max_bytes: 1_000,
            blocked_mimes: vec!["application/x-msdownload".to_owned()],
            blocked_extensions: Vec::new(),
        },
        w.accounts.clone(),
        w.remote_actors.clone(),
        w.store.clone(),
        w.store.clone(),
        w.notifier.clone(),
        w.groups.clone(),
    )
}

/// Carol's next message to Alice, in `conversation`.
pub(crate) fn from_carol(w: &World, conversation: ConversationId) -> IncomingMessage {
    IncomingMessage {
        recipient: w.alice.id,
        sender: w.carol.actor_uri.clone(),
        conversation,
        activity_uri: MessageId::generate().activity_uri(&w.carol.actor_uri),
        ciphertext: MlsCiphertext::parse(vec![5; 16]).unwrap(),
        in_reply_to: None,
        group: None,
        attachments: Vec::new(),
    }
}

pub(crate) async fn stored(w: &World, activity_uri: &str) -> Message {
    w.store
        .find_by_activity(activity_uri)
        .await
        .unwrap()
        .expect("the message was stored")
}

fn crew(w: &World) -> GroupSnapshot {
    let member = |actor_uri: &ActorUri, role| Member {
        actor_uri: actor_uri.clone(),
        role,
    };
    GroupSnapshot {
        name: Some("crew".to_owned()),
        members: vec![
            member(&w.carol.actor_uri, Role::Admin),
            member(&w.alice.actor_uri, Role::Member),
            member(&w.bob.actor_uri, Role::Member),
        ],
    }
}

#[tokio::test]
async fn a_received_dm_is_filed_under_the_id_its_sender_chose_and_announced() {
    let w = world();
    let dm = ConversationId::generate();
    let incoming = from_carol(&w, dm);
    let activity = incoming.activity_uri.clone();

    receive(&w).execute(incoming).await.unwrap();

    let message = stored(&w, &activity).await;
    assert_eq!(message.id, MessageId::of_activity(&activity));
    assert_eq!(
        (message.conversation, &message.sender),
        (dm, &w.carol.actor_uri)
    );
    assert_eq!(w.store.members(dm).await.unwrap().len(), 2);
    assert_eq!(
        w.notifier.sent(),
        vec![MessageNotice::Message(
            w.alice.id,
            MessageEvent {
                message,
                kind: ConversationKind::Dm,
                sender_address: "carol_k2m9x@idp.carol.test".to_owned(),
                sender_display_name: Some("carol_k2m9x".to_owned()),
                client_id: None,
            }
        )]
    );
}

#[tokio::test]
async fn a_received_reply_is_threaded_under_its_local_parent() {
    let w = world();
    let dm = ConversationId::generate();
    let parent = from_carol(&w, dm);
    let parent_activity = parent.activity_uri.clone();
    receive(&w).execute(parent).await.unwrap();

    for (in_reply_to, expected) in [
        (
            Some(parent_activity.clone()),
            Some(stored(&w, &parent_activity).await.id),
        ),
        (Some("https://idp.carol.test/never-seen".to_owned()), None),
    ] {
        let reply = IncomingMessage {
            in_reply_to,
            ..from_carol(&w, dm)
        };
        let activity = reply.activity_uri.clone();

        receive(&w).execute(reply).await.unwrap();

        assert_eq!(stored(&w, &activity).await.reply_to, expected);
    }
}

#[tokio::test]
async fn a_group_message_mirrors_its_roster_and_announces_the_group_once() {
    let w = world();
    let group = ConversationId::generate();

    for _ in 0..2 {
        let incoming = IncomingMessage {
            group: Some(crew(&w)),
            ..from_carol(&w, group)
        };
        receive(&w).execute(incoming).await.unwrap();
    }

    let mirrored = Conversations::find(&*w.store, group)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (mirrored.kind, mirrored.name.as_deref()),
        (ConversationKind::Group, Some("crew"))
    );
    assert_eq!(w.store.members(group).await.unwrap().len(), 3);
    let joined = w.groups.sent();
    assert_eq!(
        joined,
        vec![GroupNotice::Joined(
            w.alice.id,
            group,
            w.carol.actor_uri.clone()
        )]
    );
}

#[tokio::test]
async fn a_group_message_is_filed_in_the_group_even_when_the_pair_shares_a_dm() {
    let w = world();
    w.store
        .open_dm(&w.carol.actor_uri, &w.alice.actor_uri, None)
        .await
        .unwrap();
    let group = ConversationId::generate();
    let incoming = IncomingMessage {
        group: Some(crew(&w)),
        ..from_carol(&w, group)
    };
    let activity = incoming.activity_uri.clone();

    receive(&w).execute(incoming).await.unwrap();

    assert_eq!(stored(&w, &activity).await.conversation, group);
}

#[tokio::test]
async fn the_attachments_the_limits_admit_are_recorded_with_the_message() {
    let w = world();
    let (kept, blocked) = (AttachmentId::generate(), AttachmentId::generate());
    let offer = |id: AttachmentId, mime: &str| OfferedAttachment {
        is_document: true,
        url: Some(format!(
            "https://idp.carol.test/api/attachments/{id}/content"
        )),
        media_type: Some(mime.to_owned()),
        name: Some("file".to_owned()),
        size: Some(100),
    };
    let incoming = IncomingMessage {
        attachments: vec![
            offer(kept, "image/png"),
            offer(blocked, "application/x-msdownload"),
        ],
        ..from_carol(&w, ConversationId::generate())
    };
    let activity = incoming.activity_uri.clone();

    receive(&w).execute(incoming).await.unwrap();

    let attached: Vec<_> = stored(&w, &activity)
        .await
        .attachments
        .iter()
        .map(|a| a.id)
        .collect();
    assert_eq!(attached, vec![kept]);
}

#[tokio::test]
async fn a_received_reply_to_a_message_of_another_conversation_is_left_unthreaded() {
    let w = world();
    let in_the_group = IncomingMessage {
        group: Some(crew(&w)),
        ..from_carol(&w, ConversationId::generate())
    };
    let elsewhere = in_the_group.activity_uri.clone();
    receive(&w).execute(in_the_group).await.unwrap();
    let reply = IncomingMessage {
        in_reply_to: Some(elsewhere),
        ..from_carol(&w, ConversationId::generate())
    };
    let activity = reply.activity_uri.clone();

    receive(&w).execute(reply).await.unwrap();

    assert_eq!(stored(&w, &activity).await.reply_to, None);
}

#[tokio::test]
async fn a_group_message_from_a_non_member_is_refused_and_its_roster_ignored() {
    let w = world();
    let group = ConversationId::generate();
    receive(&w)
        .execute(IncomingMessage {
            group: Some(crew(&w)),
            ..from_carol(&w, group)
        })
        .await
        .unwrap();
    let mallory = ActorUri::parse("https://idp.mallory.test/users/mallory_k2m9x").unwrap();
    let mut forged = crew(&w);
    forged.members.push(Member {
        actor_uri: mallory.clone(),
        role: Role::Admin,
    });
    let before = w.notifier.sent().len();

    let refused = receive(&w)
        .execute(IncomingMessage {
            sender: mallory,
            group: Some(forged),
            ..from_carol(&w, group)
        })
        .await;

    assert!(
        matches!(refused, Err(MessagingError::ConversationNotFound)),
        "{refused:?}"
    );
    assert_eq!(w.store.members(group).await.unwrap().len(), 3);
    assert_eq!(w.notifier.sent().len(), before, "nothing announced");
}

#[tokio::test]
async fn a_group_new_here_is_introduced_only_by_one_of_its_members() {
    let w = world();
    let group = ConversationId::generate();
    let mut without_carol = crew(&w);
    without_carol
        .members
        .retain(|m| m.actor_uri != w.carol.actor_uri);

    let refused = receive(&w)
        .execute(IncomingMessage {
            group: Some(without_carol),
            ..from_carol(&w, group)
        })
        .await;

    assert!(
        matches!(refused, Err(MessagingError::ConversationNotFound)),
        "{refused:?}"
    );
    assert_eq!(Conversations::find(&*w.store, group).await.unwrap(), None);
}

#[tokio::test]
async fn a_roster_is_never_mirrored_into_a_dm() {
    let w = world();
    let dm = w
        .store
        .open_dm(&w.carol.actor_uri, &w.alice.actor_uri, None)
        .await
        .unwrap();

    let refused = receive(&w)
        .execute(IncomingMessage {
            group: Some(crew(&w)),
            ..from_carol(&w, dm)
        })
        .await;

    assert!(refused.is_err());
    assert_eq!(w.store.members(dm).await.unwrap().len(), 2);
}

#[tokio::test]
async fn a_redelivered_message_is_stored_and_announced_once() {
    let w = world();
    let incoming = from_carol(&w, ConversationId::generate());
    let again = IncomingMessage {
        ciphertext: incoming.ciphertext.clone(),
        activity_uri: incoming.activity_uri.clone(),
        ..from_carol(&w, incoming.conversation)
    };

    receive(&w).execute(incoming).await.unwrap();
    receive(&w).execute(again).await.unwrap();

    assert_eq!(w.notifier.sent().len(), 1);
}

#[tokio::test]
async fn a_received_group_message_is_announced_as_a_group_message() {
    let w = world();
    let incoming = IncomingMessage {
        group: Some(crew(&w)),
        ..from_carol(&w, ConversationId::generate())
    };

    receive(&w).execute(incoming).await.unwrap();

    let Some(MessageNotice::Message(to, event)) = w.notifier.sent().pop() else {
        panic!("no message announced");
    };
    assert_eq!(
        (to, event.kind, event.sender_address.as_str()),
        (
            w.alice.id,
            ConversationKind::Group,
            "carol_k2m9x@idp.carol.test"
        )
    );
}
