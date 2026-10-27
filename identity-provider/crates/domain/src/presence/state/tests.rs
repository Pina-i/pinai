use crate::identity::testing::{account, remote_actor};
use crate::messaging::{Member, Role};

use super::*;

#[test]
fn a_state_reads_from_its_wire_form_and_back() {
    for state in [
        PresenceState::Online,
        PresenceState::Away,
        PresenceState::Offline,
        PresenceState::Dnd,
    ] {
        assert_eq!(state.as_str().parse::<PresenceState>().unwrap(), state);
    }
    assert!("invisible".parse::<PresenceState>().is_err());
}

#[test]
fn a_heartbeat_brings_back_only_an_away_user() {
    assert_eq!(
        PresenceState::Away.after_heartbeat(),
        Some(PresenceState::Online)
    );
    for kept in [
        PresenceState::Online,
        PresenceState::Offline,
        PresenceState::Dnd,
    ] {
        assert_eq!(kept.after_heartbeat(), None, "{kept}");
    }
}

#[test]
fn idling_turns_only_an_online_user_away() {
    assert_eq!(
        PresenceState::Online.after_idle(),
        Some(PresenceState::Away)
    );
    for kept in [
        PresenceState::Away,
        PresenceState::Offline,
        PresenceState::Dnd,
    ] {
        assert_eq!(kept.after_idle(), None, "{kept}");
    }
}

#[test]
fn an_account_is_around_unless_it_reads_offline() {
    for around in [
        PresenceState::Online,
        PresenceState::Away,
        PresenceState::Dnd,
    ] {
        assert!(around.is_around(), "{around}");
    }
    assert!(!PresenceState::Offline.is_around());
}

#[test]
fn only_an_active_member_types_in_a_conversation() {
    let (alice, carol) = (
        account("alice").actor_uri,
        remote_actor("carol_k2m9x@idp.carol.test").actor_uri,
    );
    let members = [Member {
        actor_uri: alice.clone(),
        role: Role::Member,
    }];

    assert!(may_type(&members, &alice));
    assert!(!may_type(&members, &carol));
    assert!(!may_type(&[], &alice));
}
