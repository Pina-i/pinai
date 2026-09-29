use std::sync::Arc;

use domain::FriendshipId;
use domain::identity::testing::{InMemoryAccounts, InMemoryRemoteActors, account, remote_actor};
use domain::social::testing::{
    InMemorySocialGraph, Notice, RecordingFriendPresence, RecordingSocialNotifier,
};
use domain::social::{Direction, Friendship, FriendshipStatus, SocialGraph};

use super::*;

#[tokio::test]
async fn an_undo_ends_the_friendship_once_and_releases_the_presence() {
    let alice = account("alice");
    let carol = remote_actor("carol_k2m9x@idp.carol.test");
    let graph = Arc::new(InMemorySocialGraph::default());
    let side = Friendship {
        id: FriendshipId::generate(),
        owner: alice.id,
        friend: carol.actor_uri.clone(),
        status: FriendshipStatus::Accepted,
        direction: Direction::Outgoing,
    };
    graph.insert(side.clone());
    let notifier = Arc::new(RecordingSocialNotifier::default());
    let presence = Arc::new(RecordingFriendPresence::default());
    let receive = ReceiveUndoFollow::new(
        Arc::new(InMemoryAccounts::with([alice.clone()])),
        Arc::new(InMemoryRemoteActors::with([carol.clone()])),
        graph.clone(),
        notifier.clone(),
        presence.clone(),
    );

    receive
        .execute(alice.id, carol.actor_uri.clone())
        .await
        .unwrap();
    receive
        .execute(alice.id, carol.actor_uri.clone())
        .await
        .unwrap();

    assert_eq!(
        graph.between(alice.id, &carol.actor_uri).await.unwrap(),
        None
    );
    let sent = notifier.sent();
    let [(Notice::FriendRemoved, to, event)] = sent.as_slice() else {
        panic!("one friend_removed expected, got {sent:?}");
    };
    assert_eq!((*to, event.friendship), (alice.id, side.id));
    assert_eq!(presence.released(), vec![carol.actor_uri.clone()]);
}
