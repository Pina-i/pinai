use std::sync::Arc;

use domain::identity::ActorUri;
use domain::messaging::NewMessage;
use domain::messaging::testing::{MessageNotice, Outbound};
use domain::social::testing::{BLOCKED, KEPT_OUT_BY_THE_SETTING, StubReachability};

use super::*;
use crate::messaging::send_group_message::tests::{Group, crew};
use crate::messaging::{GroupMessageCommand, SendGroupMessage};

fn edit(g: &Group) -> EditMessage {
    edit_with(g, Arc::new(StubReachability::default()))
}

fn edit_with(g: &Group, reach: Arc<StubReachability>) -> EditMessage {
    EditMessage::new(
        g.accounts.clone(),
        g.remote_actors.clone(),
        g.store.clone(),
        g.store.clone(),
        reach,
        g.notifier.clone(),
        g.federation.clone(),
    )
}

/// A message alice sent in her DM with `with`.
async fn in_a_dm(g: &Group, with: &ActorUri) -> MessageId {
    let dm = g
        .store
        .open_dm(&g.alice.actor_uri, with, None)
        .await
        .unwrap();
    let id = MessageId::generate();
    Messages::record(
        &*g.store,
        &NewMessage {
            id,
            conversation: dm,
            sender: g.alice.actor_uri.clone(),
            ciphertext: MlsCiphertext::parse(vec![1; 8]).unwrap(),
            activity_uri: id.activity_uri(&g.alice.actor_uri),
            reply_to: None,
            attachments: Vec::new(),
        },
    )
    .await
    .unwrap();
    id
}

async fn untouched(g: &Group, id: MessageId) -> bool {
    Messages::find(&*g.store, id)
        .await
        .unwrap()
        .is_some_and(|m| m.edited_at.is_none())
}

async fn posted_by_alice(g: &Group) -> MessageId {
    let send = SendGroupMessage::new(
        2,
        g.accounts.clone(),
        g.remote_actors.clone(),
        g.store.clone(),
        g.store.clone(),
        Arc::new(domain::messaging::testing::RecordingMessageNotifier::default()),
        Arc::new(domain::messaging::testing::RecordingMessageFederation::default()),
    );
    send.execute(
        g.alice.id,
        GroupMessageCommand {
            conversation: g.id,
            ciphertext: MlsCiphertext::parse(vec![1; 8]).unwrap(),
            reply_to: None,
            attachments: Vec::new(),
        },
    )
    .await
    .unwrap()
    .message
    .id
}

fn new_ciphertext() -> MlsCiphertext {
    MlsCiphertext::parse(vec![2; 8]).unwrap()
}

#[tokio::test]
async fn an_edit_reaches_every_other_member_and_the_editors_sessions() {
    let g = crew().await;
    let id = posted_by_alice(&g).await;

    let edited = edit(&g)
        .execute(g.alice.id, id, new_ciphertext())
        .await
        .unwrap();

    let m = &edited.message;
    assert_eq!((m.id, &m.ciphertext), (id, &new_ciphertext()));
    assert!(m.edited_at.is_some());
    assert_eq!(edited.sender_display_name, "alice");
    assert_eq!(
        g.notifier.sent(),
        vec![
            MessageNotice::Edited(g.bob.id, m.clone()),
            MessageNotice::EditEchoed(g.alice.id, m.clone()),
        ]
    );
    assert_eq!(
        g.federation.sent(),
        vec![Outbound::Edit {
            from: g.alice.actor_uri.clone(),
            to: g.carol.actor_uri.clone(),
            message: id,
        }]
    );
}

#[tokio::test]
async fn only_its_sender_edits_a_message() {
    let g = crew().await;
    let id = posted_by_alice(&g).await;

    let refused = edit(&g).execute(g.bob.id, id, new_ciphertext()).await;

    assert!(matches!(refused, Err(MessagingError::MessageNotFound)));
    assert!(g.notifier.sent().is_empty());
}

#[tokio::test]
async fn an_edit_in_a_dm_with_someone_the_editor_blocked_is_refused() {
    let g = crew().await;
    let reach = Arc::new(StubReachability::default());

    for with in [g.bob.actor_uri.clone(), g.carol.actor_uri.clone()] {
        let id = in_a_dm(&g, &with).await;
        reach.set(g.alice.id, &with, BLOCKED);

        let refused = edit_with(&g, reach.clone())
            .execute(g.alice.id, id, new_ciphertext())
            .await;

        assert!(
            matches!(refused, Err(MessagingError::YouBlocked)),
            "{:?}",
            refused.map(|_| ())
        );
        assert!(untouched(&g, id).await);
    }
    assert!(g.notifier.sent().is_empty());
    assert!(g.federation.sent().is_empty());
}

#[tokio::test]
async fn an_edit_never_reaches_a_dm_partner_who_cannot_be_reached_whatever_the_cause() {
    let mut refusals = Vec::new();
    for kept_out in [BLOCKED, KEPT_OUT_BY_THE_SETTING] {
        let g = crew().await;
        let id = in_a_dm(&g, &g.bob.actor_uri).await;
        let reach = Arc::new(StubReachability::default());
        reach.set(g.bob.id, &g.alice.actor_uri, kept_out);

        let refused = edit_with(&g, reach)
            .execute(g.alice.id, id, new_ciphertext())
            .await;

        refusals.push(format!("{:?}", refused.map(|_| ())));
        assert!(untouched(&g, id).await);
        assert!(g.notifier.sent().is_empty());
    }
    assert_eq!(refusals, vec!["Err(Undeliverable)"; 2]);
}

#[tokio::test]
async fn an_edit_in_a_group_is_never_checked() {
    let g = crew().await;
    let id = posted_by_alice(&g).await;
    let reach = Arc::new(StubReachability::default());
    reach.set(g.alice.id, &g.bob.actor_uri, BLOCKED);
    reach.set(g.bob.id, &g.alice.actor_uri, BLOCKED);

    let edited = edit_with(&g, reach)
        .execute(g.alice.id, id, new_ciphertext())
        .await;

    assert!(edited.is_ok());
}
