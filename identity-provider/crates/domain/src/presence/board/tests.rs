use crate::identity::testing::account;

use super::*;

#[test]
fn the_board_holds_the_last_state_heard() {
    let board = PresenceBoard::default();
    let alice = account("alice").actor_uri;
    let unheard = (board.heard(&alice), board.state(&alice));

    board.set(&alice, PresenceState::Dnd);
    board.set(&alice, PresenceState::Away);

    assert_eq!(unheard, (None, PresenceState::Offline));
    assert_eq!(
        (board.heard(&alice), board.state(&alice)),
        (Some(PresenceState::Away), PresenceState::Away)
    );
}
