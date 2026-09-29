use domain::messaging::Messages;
use domain::messaging::testing::contract::new_message;

use super::*;
use crate::messaging::send_group_message::tests::crew;

#[tokio::test]
async fn a_member_marks_a_conversation_read() {
    let g = crew().await;
    g.store
        .record(&new_message(g.id, &g.bob.actor_uri))
        .await
        .unwrap();
    let mark = MarkRead::new(g.accounts.clone(), g.store.clone());

    mark.execute(g.alice.id, g.id).await.unwrap();

    let listed = g
        .store
        .list_for(g.alice.id, &g.alice.actor_uri)
        .await
        .unwrap();
    assert_eq!(listed[0].unread_count, 0);
}

#[tokio::test]
async fn only_a_member_marks_a_conversation_read() {
    let g = crew().await;
    let mark = MarkRead::new(g.accounts.clone(), g.store.clone());

    let refused = mark.execute(g.eve.id, g.id).await;

    assert!(matches!(refused, Err(MessagingError::ConversationNotFound)));
}
