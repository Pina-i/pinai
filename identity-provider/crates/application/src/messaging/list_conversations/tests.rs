use super::*;
use crate::messaging::send_group_message::tests::crew;

#[tokio::test]
async fn the_list_holds_the_callers_conversations_only() {
    let g = crew().await;
    let list = ListConversations::new(g.accounts.clone(), g.store.clone());

    let alices = list.execute(g.alice.id).await.unwrap();
    let eves = list.execute(g.eve.id).await.unwrap();

    assert_eq!(alices.iter().map(|s| s.id).collect::<Vec<_>>(), vec![g.id]);
    assert!(eves.is_empty());
}
