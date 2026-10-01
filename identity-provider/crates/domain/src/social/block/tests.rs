use super::*;
use crate::FriendshipId;
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

#[test]
fn a_friendship_or_a_request_the_blocker_sent_ends_as_an_unfriend() {
    for (status, direction) in [
        (FriendshipStatus::Accepted, Direction::Outgoing),
        (FriendshipStatus::Accepted, Direction::Incoming),
        (FriendshipStatus::Pending, Direction::Outgoing),
    ] {
        assert_eq!(
            Ending::of(&side(status, direction)),
            Ending::Unfriend,
            "{status:?} {direction:?}"
        );
    }
}

#[test]
fn a_request_the_blocked_account_sent_is_declined() {
    assert_eq!(
        Ending::of(&side(FriendshipStatus::Pending, Direction::Incoming)),
        Ending::Decline
    );
}

fn blocked(n: usize) -> Vec<BlockedActor> {
    (0..n)
        .map(|i| BlockedActor {
            actor: ActorUri::parse(&format!("https://idp.bob.test/users/bob_{i:05}")).unwrap(),
            display_name: None,
            avatar_url: None,
            blocked_at: OffsetDateTime::UNIX_EPOCH,
        })
        .collect()
}

#[test]
fn a_block_list_holds_a_thousand_actors() {
    let newcomer = ActorUri::parse("https://idp.carol.test/users/carol_x1y2z").unwrap();

    assert!(room_for(&blocked(MAX_BLOCKS - 1), &newcomer).is_ok());
    assert!(matches!(
        room_for(&blocked(MAX_BLOCKS), &newcomer),
        Err(SocialError::BlockListFull)
    ));
}

#[test]
fn a_full_list_still_takes_an_actor_already_on_it() {
    let full = blocked(MAX_BLOCKS);

    assert!(room_for(&full, &full[7].actor).is_ok());
}
