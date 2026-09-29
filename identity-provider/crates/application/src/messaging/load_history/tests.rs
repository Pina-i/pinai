use domain::identity::ActorUri;
use domain::messaging::testing::contract::new_message;

use super::*;
use crate::messaging::send_group_message::tests::{Group, crew};

fn load(g: &Group) -> LoadHistory {
    LoadHistory::new(
        g.accounts.clone(),
        g.remote_actors.clone(),
        g.store.clone(),
        g.store.clone(),
    )
}

async fn post(g: &Group, sender: &ActorUri) -> Message {
    g.store.record(&new_message(g.id, sender)).await.unwrap()
}

async fn unread(g: &Group) -> i64 {
    let listed = g
        .store
        .list_for(g.alice.id, &g.alice.actor_uri)
        .await
        .unwrap();
    listed[0].unread_count
}

#[tokio::test]
async fn a_page_names_each_sender_as_this_instance_knows_them() {
    let g = crew().await;
    let dave = ActorUri::parse("https://idp.dave.test/users/dave_k2m9x").unwrap();
    for sender in [&g.bob.actor_uri, &g.carol.actor_uri, &dave] {
        post(&g, sender).await;
    }

    let page = load(&g)
        .execute(g.alice.id, g.id, None, None)
        .await
        .unwrap();

    let names: Vec<_> = page
        .iter()
        .map(|e| (e.message.sender.clone(), e.sender_display_name.clone()))
        .collect();
    assert_eq!(
        names,
        vec![
            (dave, None),
            (g.carol.actor_uri.clone(), Some("carol_k2m9x".to_owned())),
            (g.bob.actor_uri.clone(), Some("bob".to_owned())),
        ]
    );
}

#[tokio::test]
async fn only_a_member_reads_a_conversation() {
    let g = crew().await;

    let refused = load(&g).execute(g.eve.id, g.id, None, None).await;

    assert!(matches!(refused, Err(MessagingError::ConversationNotFound)));
}

#[tokio::test]
async fn the_first_page_marks_the_conversation_read_and_older_pages_do_not() {
    let g = crew().await;
    let first = post(&g, &g.bob.actor_uri).await;
    assert_eq!(unread(&g).await, 1);

    load(&g)
        .execute(g.alice.id, g.id, None, None)
        .await
        .unwrap();
    assert_eq!(unread(&g).await, 0);

    post(&g, &g.bob.actor_uri).await;
    let cursor = HistoryCursor {
        created_at: first.created_at,
        id: first.id,
    };
    load(&g)
        .execute(g.alice.id, g.id, Some(cursor), None)
        .await
        .unwrap();
    assert_eq!(unread(&g).await, 1);
}

#[tokio::test]
async fn a_page_holds_50_messages_unless_asked_and_never_more_than_100() {
    let g = crew().await;
    for _ in 0..101 {
        post(&g, &g.bob.actor_uri).await;
    }

    let default = load(&g)
        .execute(g.alice.id, g.id, None, None)
        .await
        .unwrap();
    let asked = load(&g)
        .execute(g.alice.id, g.id, None, Some(500))
        .await
        .unwrap();

    assert_eq!((default.len(), asked.len()), (50, 100));
}
