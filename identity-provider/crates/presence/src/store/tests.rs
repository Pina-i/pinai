use super::*;

const ALICE: &str = "https://idp.alice.com/users/alice";
const BOB: &str = "https://idp.bob.com/users/bob";
const CAROL: &str = "https://idp.carol.com/users/carol";

fn uris(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

// ─── Defaulting ──────────────────────────────────────────────────────────────

/// The store holds no state across a restart, so anyone it has not heard from
/// must read as offline rather than as unknown.
#[test]
fn an_actor_the_store_has_not_heard_from_is_offline() {
    assert_eq!(PresenceStore::new().get(ALICE), PresenceState::Offline);
}

#[test]
fn a_new_store_is_empty() {
    let store = PresenceStore::new();

    assert!(store.snapshot(&uris(&[ALICE, BOB])).is_empty());
}

// ─── Recording state ─────────────────────────────────────────────────────────

#[test]
fn a_recorded_state_is_read_back() {
    let store = PresenceStore::new();
    store.set(ALICE, PresenceState::Online);

    assert_eq!(store.get(ALICE), PresenceState::Online);
}

#[test]
fn the_most_recent_state_wins() {
    let store = PresenceStore::new();
    store.set(ALICE, PresenceState::Online);
    store.set(ALICE, PresenceState::Away);
    store.set(ALICE, PresenceState::Dnd);

    assert_eq!(store.get(ALICE), PresenceState::Dnd);
}

#[test]
fn actors_are_tracked_independently() {
    let store = PresenceStore::new();
    store.set(ALICE, PresenceState::Online);
    store.set(BOB, PresenceState::Away);

    assert_eq!(store.get(ALICE), PresenceState::Online);
    assert_eq!(store.get(BOB), PresenceState::Away);
}

/// Offline is a state a peer actively reports, not only the absence of one —
/// storing it must not be confused with having no entry.
#[test]
fn an_explicitly_offline_actor_is_still_an_entry() {
    let store = PresenceStore::new();
    store.set(ALICE, PresenceState::Offline);

    assert_eq!(store.get(ALICE), PresenceState::Offline);
    assert_eq!(store.snapshot(&uris(&[ALICE])).len(), 1);
}

// ─── Removal ─────────────────────────────────────────────────────────────────

#[test]
fn a_removed_actor_reads_as_offline_again() {
    let store = PresenceStore::new();
    store.set(ALICE, PresenceState::Online);
    store.remove(ALICE);

    assert_eq!(store.get(ALICE), PresenceState::Offline);
    assert!(store.snapshot(&uris(&[ALICE])).is_empty());
}

#[test]
fn removing_one_actor_leaves_the_others() {
    let store = PresenceStore::new();
    store.set(ALICE, PresenceState::Online);
    store.set(BOB, PresenceState::Online);
    store.remove(ALICE);

    assert_eq!(store.get(BOB), PresenceState::Online);
}

#[test]
fn removing_an_actor_that_was_never_present_is_harmless() {
    let store = PresenceStore::new();
    store.remove(ALICE);

    assert_eq!(store.get(ALICE), PresenceState::Offline);
}

// ─── Bulk reads ──────────────────────────────────────────────────────────────

/// The sidebar asks for a fixed list of actors and renders them in the order it
/// asked, so every requested URI must come back, in position.
#[test]
fn a_bulk_read_answers_for_every_actor_asked_about() {
    let store = PresenceStore::new();
    store.set(ALICE, PresenceState::Online);
    store.set(CAROL, PresenceState::Dnd);

    let result = store.get_many(&uris(&[ALICE, BOB, CAROL]));

    assert_eq!(
        result,
        vec![
            (ALICE.to_string(), PresenceState::Online),
            (BOB.to_string(), PresenceState::Offline),
            (CAROL.to_string(), PresenceState::Dnd),
        ]
    );
}

#[test]
fn a_bulk_read_of_nothing_returns_nothing() {
    let store = PresenceStore::new();
    store.set(ALICE, PresenceState::Online);

    assert!(store.get_many(&[]).is_empty());
}

// ─── Snapshot ────────────────────────────────────────────────────────────────

/// Snapshot feeds SSE reconnect replay, which should re-send only states the
/// store actually knows — unlike `get_many`, absence is not reported as offline.
#[test]
fn a_snapshot_omits_actors_the_store_knows_nothing_about() {
    let store = PresenceStore::new();
    store.set(ALICE, PresenceState::Online);

    let snapshot = store.snapshot(&uris(&[ALICE, BOB]));

    assert_eq!(snapshot.len(), 1);
    assert_eq!(snapshot[0].0, ALICE);
    assert_eq!(snapshot[0].1, PresenceState::Online);
}

#[test]
fn a_snapshot_is_limited_to_the_actors_asked_about() {
    let store = PresenceStore::new();
    store.set(ALICE, PresenceState::Online);
    store.set(BOB, PresenceState::Away);

    let snapshot = store.snapshot(&uris(&[BOB]));

    assert_eq!(snapshot.len(), 1);
    assert_eq!(snapshot[0].0, BOB);
}

/// The instant is what lets a replay say how stale a state is, so re-setting an
/// actor must move it forward rather than keep the original observation time.
#[test]
fn re_recording_a_state_refreshes_its_timestamp() {
    let store = PresenceStore::new();
    store.set(ALICE, PresenceState::Online);
    let first = store.snapshot(&uris(&[ALICE]))[0].2;

    std::thread::sleep(std::time::Duration::from_millis(5));
    store.set(ALICE, PresenceState::Online);
    let second = store.snapshot(&uris(&[ALICE]))[0].2;

    assert!(second > first, "timestamp should advance on a repeated set");
}

// ─── Wire representation ─────────────────────────────────────────────────────
// Clients match on these strings; they are part of the WS contract.

#[test]
fn every_state_serialises_lowercase() {
    for (state, expected) in [
        (PresenceState::Online, "online"),
        (PresenceState::Away, "away"),
        (PresenceState::Offline, "offline"),
        (PresenceState::Dnd, "dnd"),
    ] {
        assert_eq!(serde_json::to_value(state).unwrap(), expected);
        assert_eq!(
            state.to_string(),
            expected,
            "Display should match the wire form"
        );
    }
}

#[test]
fn a_state_survives_a_round_trip_through_the_wire_form() {
    for state in [
        PresenceState::Online,
        PresenceState::Away,
        PresenceState::Offline,
        PresenceState::Dnd,
    ] {
        let json = serde_json::to_value(state).unwrap();
        let parsed: PresenceState = serde_json::from_value(json).unwrap();
        assert_eq!(parsed, state);
    }
}

#[test]
fn an_unknown_state_from_the_wire_is_rejected() {
    assert!(serde_json::from_value::<PresenceState>(serde_json::json!("invisible")).is_err());
}
