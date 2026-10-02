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
        g.store.clone(),
    )
}

async fn post(g: &Group, sender: &ActorUri) -> Message {
    Messages::record(&*g.store, &new_message(g.id, sender))
        .await
        .unwrap()
}

/// The messages of a page, its events left out.
fn messages(page: Vec<TimelineEntry>) -> Vec<HistoryEntry> {
    page.into_iter()
        .filter_map(|entry| match entry {
            TimelineEntry::Message(message) => Some(message),
            TimelineEntry::Event(_) => None,
        })
        .collect()
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
        .execute(g.alice.id, g.id, None, None, false)
        .await
        .unwrap();

    let names: Vec<_> = messages(page)
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

    let refused = load(&g).execute(g.eve.id, g.id, None, None, false).await;

    assert!(matches!(refused, Err(MessagingError::ConversationNotFound)));
}

#[tokio::test]
async fn a_removed_member_reads_up_to_their_removal_until_they_clear_the_group() {
    let g = crew().await;
    let before = post(&g, &g.alice.actor_uri).await;
    g.store
        .remove_member(g.id, &g.bob.actor_uri, Some(&g.alice.actor_uri), None)
        .await
        .unwrap();
    post(&g, &g.alice.actor_uri).await;

    let page = load(&g)
        .execute(g.bob.id, g.id, None, None, false)
        .await
        .unwrap();
    assert_eq!(
        messages(page)
            .iter()
            .map(|e| e.message.id)
            .collect::<Vec<_>>(),
        vec![before.id]
    );

    g.store.dismiss(g.id, &g.bob.actor_uri).await.unwrap();
    let cleared = load(&g).execute(g.bob.id, g.id, None, None, false).await;
    assert!(matches!(cleared, Err(MessagingError::ConversationNotFound)));
}

#[tokio::test]
async fn one_who_left_reads_nothing_more() {
    let g = crew().await;
    post(&g, &g.alice.actor_uri).await;
    g.store
        .remove_member(g.id, &g.bob.actor_uri, None, None)
        .await
        .unwrap();

    let refused = load(&g).execute(g.bob.id, g.id, None, None, false).await;

    assert!(matches!(refused, Err(MessagingError::ConversationNotFound)));
}

#[tokio::test]
async fn the_first_page_marks_the_conversation_read_and_older_pages_do_not() {
    let g = crew().await;
    let first = post(&g, &g.bob.actor_uri).await;
    assert_eq!(unread(&g).await, 1);

    load(&g)
        .execute(g.alice.id, g.id, None, None, false)
        .await
        .unwrap();
    assert_eq!(unread(&g).await, 0);

    post(&g, &g.bob.actor_uri).await;
    let cursor = HistoryCursor {
        created_at: first.created_at,
        id: first.id.as_uuid(),
    };
    load(&g)
        .execute(g.alice.id, g.id, Some(cursor), None, false)
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
        .execute(g.alice.id, g.id, None, None, false)
        .await
        .unwrap();
    let asked = load(&g)
        .execute(g.alice.id, g.id, None, Some(500), false)
        .await
        .unwrap();

    assert_eq!((default.len(), asked.len()), (50, 100));
}

fn event_at(g: &Group, at: time::OffsetDateTime) -> domain::messaging::GroupEvent {
    domain::messaging::GroupEvent::created(g.id, g.alice.actor_uri.clone(), at)
}

#[tokio::test]
async fn a_page_holds_the_groups_events_its_reader_saw_between_its_messages() {
    use domain::messaging::GroupEvents;
    let g = crew().await;
    let message = post(&g, &g.bob.actor_uri).await;
    let before_anyone = event_at(&g, message.created_at - time::Duration::hours(1));
    let later = event_at(&g, message.created_at + time::Duration::hours(1));
    for event in [&before_anyone, &later] {
        GroupEvents::record(&*g.store, event).await.unwrap();
    }
    let ids = |page: Vec<TimelineEntry>| -> Vec<u128> {
        page.iter()
            .map(|entry| match entry {
                TimelineEntry::Message(m) => m.message.id.as_uuid().as_u128(),
                TimelineEntry::Event(e) => e.event.id.as_uuid().as_u128(),
            })
            .collect()
    };

    let with_events = load(&g)
        .execute(g.alice.id, g.id, None, None, true)
        .await
        .unwrap();
    let without = load(&g)
        .execute(g.alice.id, g.id, None, None, false)
        .await
        .unwrap();
    let newest = load(&g)
        .execute(g.alice.id, g.id, None, Some(1), true)
        .await
        .unwrap();

    assert_eq!(
        ids(with_events),
        vec![later.id.as_uuid().as_u128(), message.id.as_uuid().as_u128()],
        "newest first, nothing from before the reader joined"
    );
    assert_eq!(ids(without), vec![message.id.as_uuid().as_u128()]);
    assert_eq!(ids(newest), vec![later.id.as_uuid().as_u128()]);
}

#[tokio::test]
async fn a_removed_member_sees_no_event_from_after_their_removal() {
    use domain::messaging::GroupEvents;
    let g = crew().await;
    g.store
        .remove_member(g.id, &g.bob.actor_uri, Some(&g.alice.actor_uri), None)
        .await
        .unwrap();
    let after = event_at(
        &g,
        time::OffsetDateTime::now_utc() + time::Duration::hours(1),
    );
    GroupEvents::record(&*g.store, &after).await.unwrap();

    let page = load(&g)
        .execute(g.bob.id, g.id, None, None, true)
        .await
        .unwrap();

    assert!(page.is_empty());
}
