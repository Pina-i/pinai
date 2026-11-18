use super::*;
use crate::UserId;

fn side(status: FriendshipStatus, direction: Direction) -> Friendship {
    Friendship {
        id: FriendshipId::generate(),
        owner: UserId::generate(),
        friend: ActorUri::parse("https://idp.bob.test/users/bob_k2m9x").unwrap(),
        status,
        direction,
    }
}

fn ties(blocked: bool, side: Option<Friendship>) -> Ties {
    Ties { blocked, side }
}

const SIDES: [(FriendshipStatus, Direction); 4] = [
    (FriendshipStatus::Accepted, Direction::Outgoing),
    (FriendshipStatus::Accepted, Direction::Incoming),
    (FriendshipStatus::Pending, Direction::Incoming),
    (FriendshipStatus::Pending, Direction::Outgoing),
];

#[test]
fn a_block_shows_whatever_else_holds() {
    assert_eq!(ties(true, None).standing(), Standing::Blocked);
    for (status, direction) in SIDES {
        assert_eq!(
            ties(true, Some(side(status, direction))).standing(),
            Standing::Blocked,
            "{status:?} {direction:?}"
        );
    }
}

#[test]
fn an_accepted_side_is_a_friend_whoever_asked() {
    for direction in [Direction::Outgoing, Direction::Incoming] {
        assert_eq!(
            ties(false, Some(side(FriendshipStatus::Accepted, direction))).standing(),
            Standing::Friend
        );
    }
}

#[test]
fn a_pending_side_is_a_request_received_with_its_id_or_one_sent() {
    let received = side(FriendshipStatus::Pending, Direction::Incoming);
    let id = received.id;

    assert_eq!(
        ties(false, Some(received)).standing(),
        Standing::RequestReceived(id)
    );
    assert_eq!(
        ties(
            false,
            Some(side(FriendshipStatus::Pending, Direction::Outgoing))
        )
        .standing(),
        Standing::RequestSent
    );
}

#[test]
fn without_a_block_or_a_side_they_are_unrelated() {
    assert_eq!(Ties::default().standing(), Standing::Unrelated);
}
