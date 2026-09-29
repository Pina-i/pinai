use std::sync::Arc;

use domain::messaging::testing::{MessageNotice, Outbound};

use super::*;
use crate::messaging::send_group_message::tests::{Group, crew};
use crate::messaging::{GroupMessageCommand, SendGroupMessage};

fn edit(g: &Group) -> EditMessage {
    EditMessage::new(
        g.accounts.clone(),
        g.remote_actors.clone(),
        g.store.clone(),
        g.store.clone(),
        g.notifier.clone(),
        g.federation.clone(),
    )
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
