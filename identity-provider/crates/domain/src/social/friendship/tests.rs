use super::*;
use crate::identity::ActorUri;
use crate::{FriendshipId, UserId};

fn friendship(owner: UserId, status: FriendshipStatus, direction: Direction) -> Friendship {
    Friendship {
        id: FriendshipId::generate(),
        owner,
        friend: ActorUri::parse("https://idp.bob.test/users/bob_k2m9x").unwrap(),
        status,
        direction,
    }
}

#[test]
fn only_the_owner_of_a_pending_incoming_request_may_answer_it() {
    let alice = UserId::generate();
    let request = friendship(alice, FriendshipStatus::Pending, Direction::Incoming);

    assert!(request.answerable_by(alice).is_ok());
    assert!(matches!(
        request.answerable_by(UserId::generate()),
        Err(SocialError::NotYours)
    ));
    for (status, direction) in [
        (FriendshipStatus::Pending, Direction::Outgoing),
        (FriendshipStatus::Accepted, Direction::Incoming),
    ] {
        assert!(matches!(
            friendship(alice, status, direction).answerable_by(alice),
            Err(SocialError::NotAnIncomingRequest)
        ));
    }
}

#[test]
fn a_request_never_reopens_an_accepted_friendship() {
    let alice = UserId::generate();

    assert!(Friendship::requestable(None).is_ok());
    for direction in [Direction::Outgoing, Direction::Incoming] {
        let pending = friendship(alice, FriendshipStatus::Pending, direction);
        assert!(Friendship::requestable(Some(&pending)).is_ok());
    }
    let accepted = friendship(alice, FriendshipStatus::Accepted, Direction::Outgoing);
    assert!(matches!(
        Friendship::requestable(Some(&accepted)),
        Err(SocialError::AlreadyFriends)
    ));
}
