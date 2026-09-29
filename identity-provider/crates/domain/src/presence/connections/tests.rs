use crate::identity::testing::account;

use super::*;

fn start() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap()
}

#[test]
fn a_connection_silent_past_the_threshold_is_idle_until_it_beats() {
    let tracker = ConnectionTracker::default();
    let alice = account("alice");
    let conn = ConnectionId::generate();
    tracker.register(alice.id, conn, alice.actor_uri.clone(), start());

    let before = tracker.idle_actors(start() + AWAY_AFTER - Duration::seconds(1));
    let after = tracker.idle_actors(start() + AWAY_AFTER + Duration::seconds(1));
    tracker.touch(alice.id, conn, start() + AWAY_AFTER);
    let beaten = tracker.idle_actors(start() + AWAY_AFTER + Duration::seconds(1));

    assert!(before.is_empty());
    assert_eq!(after, vec![alice.actor_uri.clone()]);
    assert!(beaten.is_empty());
}

#[test]
fn a_closed_connection_is_never_idle_and_an_account_is_listed_once() {
    let tracker = ConnectionTracker::default();
    let (alice, bob) = (account("alice"), account("bob"));
    let gone = ConnectionId::generate();
    tracker.register(bob.id, gone, bob.actor_uri.clone(), start());
    tracker.unregister(bob.id, gone);
    for _ in 0..2 {
        tracker.register(
            alice.id,
            ConnectionId::generate(),
            alice.actor_uri.clone(),
            start(),
        );
    }

    let idle = tracker.idle_actors(start() + AWAY_AFTER + Duration::minutes(1));

    assert_eq!(idle, vec![alice.actor_uri]);
}

#[test]
fn an_account_is_idle_only_when_every_connection_is() {
    let tracker = ConnectionTracker::default();
    let alice = account("alice");
    let (laptop, phone) = (ConnectionId::generate(), ConnectionId::generate());
    tracker.register(alice.id, laptop, alice.actor_uri.clone(), start());
    tracker.register(alice.id, phone, alice.actor_uri.clone(), start());
    tracker.touch(alice.id, laptop, start() + AWAY_AFTER);

    let one_live = tracker.idle_actors(start() + AWAY_AFTER + Duration::seconds(1));
    tracker.unregister(alice.id, laptop);
    let none_live = tracker.idle_actors(start() + AWAY_AFTER + Duration::seconds(1));

    assert!(one_live.is_empty(), "the laptop is still in use");
    assert_eq!(none_live, vec![alice.actor_uri]);
}
