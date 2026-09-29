use domain::ConversationId;
use domain::messaging::testing::MessageNotice;

use super::*;
use crate::messaging::ReceiveMessage;
use crate::messaging::receive_message::tests::{from_carol, stored, world};
use domain::messaging::AttachmentLimits;

async fn a_message_from_carol(w: &crate::messaging::receive_message::tests::World) -> String {
    let incoming = from_carol(w, ConversationId::generate());
    let activity = incoming.activity_uri.clone();
    ReceiveMessage::new(
        AttachmentLimits {
            max_files: 5,
            max_bytes: 1_000,
            blocked_mimes: Vec::new(),
            blocked_extensions: Vec::new(),
        },
        w.accounts.clone(),
        w.remote_actors.clone(),
        w.store.clone(),
        w.store.clone(),
        std::sync::Arc::new(domain::messaging::testing::RecordingMessageNotifier::default()),
        std::sync::Arc::new(domain::messaging::testing::RecordingGroupNotifier::default()),
    )
    .execute(incoming)
    .await
    .unwrap();
    activity
}

fn new_ciphertext() -> MlsCiphertext {
    MlsCiphertext::parse(vec![6; 16]).unwrap()
}

#[tokio::test]
async fn a_received_edit_replaces_the_ciphertext_and_is_announced() {
    let w = world();
    let activity = a_message_from_carol(&w).await;

    ReceiveEdit::new(w.store.clone(), w.notifier.clone())
        .execute(IncomingEdit {
            recipient: w.alice.id,
            sender: w.carol.actor_uri.clone(),
            activity_uri: activity.clone(),
            ciphertext: new_ciphertext(),
        })
        .await
        .unwrap();

    let edited = stored(&w, &activity).await;
    assert_eq!(edited.ciphertext, new_ciphertext());
    assert_eq!(
        w.notifier.sent(),
        vec![MessageNotice::Edited(w.alice.id, edited)]
    );
}

#[tokio::test]
async fn an_edit_from_anyone_but_its_sender_changes_nothing() {
    let w = world();
    let activity = a_message_from_carol(&w).await;

    ReceiveEdit::new(w.store.clone(), w.notifier.clone())
        .execute(IncomingEdit {
            recipient: w.alice.id,
            sender: w.bob.actor_uri.clone(),
            activity_uri: activity.clone(),
            ciphertext: new_ciphertext(),
        })
        .await
        .unwrap();

    assert_ne!(stored(&w, &activity).await.ciphertext, new_ciphertext());
    assert!(w.notifier.sent().is_empty());
}
