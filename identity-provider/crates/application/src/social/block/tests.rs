use std::sync::Arc;

use domain::FriendshipId;
use domain::identity::testing::{InMemoryAccounts, InMemoryRemoteActors, account, remote_actor};
use domain::identity::{Account, RemoteActor};
use domain::social::testing::{
    InMemorySocialGraph, Notice, RecordingFriendPresence, RecordingSocialFederation,
    RecordingSocialNotifier, Sent,
};
use domain::social::{Direction, Friendship, FriendshipStatus, MAX_BLOCKS, SocialGraph};

use super::*;

struct World {
    alice: Account,
    bob: Account,
    remote_carol: RemoteActor,
    graph: Arc<InMemorySocialGraph>,
    notifier: Arc<RecordingSocialNotifier>,
    federation: Arc<RecordingSocialFederation>,
    presence: Arc<RecordingFriendPresence>,
    block: Block,
    unblock: Unblock,
    list: ListBlocks,
}

fn world() -> World {
    let (alice, bob) = (account("alice"), account("bob"));
    let remote_carol = remote_actor("carol_k2m9x@idp.carol.test");
    let accounts = Arc::new(InMemoryAccounts::with([alice.clone(), bob.clone()]));
    let remote = Arc::new(InMemoryRemoteActors::with([remote_carol.clone()]));
    let graph = Arc::new(InMemorySocialGraph::default());
    let notifier = Arc::new(RecordingSocialNotifier::default());
    let federation = Arc::new(RecordingSocialFederation::default());
    let presence = Arc::new(RecordingFriendPresence::default());
    World {
        block: Block::new(
            accounts.clone(),
            remote.clone(),
            graph.clone(),
            notifier.clone(),
            federation.clone(),
            presence.clone(),
        ),
        unblock: Unblock::new(graph.clone(), notifier.clone()),
        list: ListBlocks::new(graph.clone()),
        alice,
        bob,
        remote_carol,
        graph,
        notifier,
        federation,
        presence,
    }
}

fn side(
    owner: &Account,
    friend: &RemoteActor,
    status: FriendshipStatus,
    direction: Direction,
) -> Friendship {
    Friendship {
        id: FriendshipId::generate(),
        owner: owner.id,
        friend: friend.actor_uri.clone(),
        status,
        direction,
    }
}

#[tokio::test]
async fn blocking_a_local_friend_ends_the_friendship_as_an_unfriend_would() {
    let w = world();
    let request = w
        .graph
        .record_local_request(&w.bob, &w.alice)
        .await
        .unwrap()
        .target_side;
    w.graph.accept(&request, &w.alice).await.unwrap();
    let bobs_side = w
        .graph
        .between(w.bob.id, &w.alice.actor_uri)
        .await
        .unwrap()
        .unwrap();

    w.block
        .execute(w.alice.id, w.bob.actor_uri.clone())
        .await
        .unwrap();

    let sent = w.notifier.sent();
    assert_eq!(sent.len(), 1);
    let (notice, to, event) = &sent[0];
    assert_eq!(
        (*notice, *to, event.friendship),
        (Notice::FriendRemoved, w.bob.id, bobs_side.id)
    );
    assert_eq!(event.actor_uri, w.alice.actor_uri);
    assert_eq!(
        event.conversation, None,
        "an unfriend's own event, naming no block"
    );
    assert!(w.graph.friends(w.alice.id).await.unwrap().is_empty());
    assert!(w.graph.friends(w.bob.id).await.unwrap().is_empty());
}

#[tokio::test]
async fn blocking_a_local_account_that_asked_to_be_friends_declines_its_request_unannounced() {
    let w = world();
    w.graph
        .record_local_request(&w.bob, &w.alice)
        .await
        .unwrap();

    w.block
        .execute(w.alice.id, w.bob.actor_uri.clone())
        .await
        .unwrap();

    assert!(
        w.notifier.sent().is_empty(),
        "a declined request just stops existing"
    );
    assert_eq!(
        w.graph.between(w.bob.id, &w.alice.actor_uri).await.unwrap(),
        None
    );
}

#[tokio::test]
async fn blocking_a_remote_friend_undoes_the_follow_and_releases_their_presence() {
    let w = world();
    w.graph.insert(side(
        &w.alice,
        &w.remote_carol,
        FriendshipStatus::Accepted,
        Direction::Outgoing,
    ));

    w.block
        .execute(w.alice.id, w.remote_carol.actor_uri.clone())
        .await
        .unwrap();

    assert_eq!(
        w.federation.sent(),
        vec![Sent::UndoFollow {
            from: w.alice.actor_uri.clone(),
            to: w.remote_carol.actor_uri.clone(),
        }]
    );
    assert_eq!(
        w.presence.released(),
        vec![w.remote_carol.actor_uri.clone()]
    );
}

#[tokio::test]
async fn blocking_a_remote_account_that_asked_to_be_friends_rejects_its_follow() {
    let w = world();
    let request = side(
        &w.alice,
        &w.remote_carol,
        FriendshipStatus::Pending,
        Direction::Incoming,
    );
    w.graph.insert(request.clone());

    w.block
        .execute(w.alice.id, w.remote_carol.actor_uri.clone())
        .await
        .unwrap();

    assert_eq!(
        w.federation.sent(),
        vec![Sent::Reject {
            from: w.alice.actor_uri.clone(),
            to: w.remote_carol.actor_uri.clone(),
            request: request.id,
        }]
    );
}

#[tokio::test]
async fn blocking_again_or_someone_never_befriended_ends_nothing_and_tells_no_one() {
    let w = world();

    w.block
        .execute(w.alice.id, w.remote_carol.actor_uri.clone())
        .await
        .unwrap();
    w.block
        .execute(w.alice.id, w.remote_carol.actor_uri.clone())
        .await
        .unwrap();

    assert!(w.federation.sent().is_empty());
    assert!(w.notifier.sent().is_empty());
    assert_eq!(w.list.execute(w.alice.id).await.unwrap().len(), 1);
}

#[tokio::test]
async fn every_session_of_the_blocker_hears_of_a_change_to_its_blocks() {
    let w = world();

    w.block
        .execute(w.alice.id, w.bob.actor_uri.clone())
        .await
        .unwrap();
    w.unblock
        .execute(w.alice.id, w.bob.actor_uri.clone())
        .await
        .unwrap();

    assert_eq!(w.notifier.blocks_updated(), vec![w.alice.id, w.alice.id]);
}

#[tokio::test]
async fn an_account_cannot_block_itself() {
    let w = world();

    let refused = w.block.execute(w.alice.id, w.alice.actor_uri.clone()).await;

    assert!(
        matches!(refused, Err(SocialError::SelfBlock)),
        "{refused:?}"
    );
    assert!(w.list.execute(w.alice.id).await.unwrap().is_empty());
}

#[tokio::test]
async fn a_full_block_list_is_refused_before_anything_ends() {
    let w = world();
    let request = w
        .graph
        .record_local_request(&w.bob, &w.alice)
        .await
        .unwrap()
        .target_side;
    w.graph.accept(&request, &w.alice).await.unwrap();
    for i in 0..MAX_BLOCKS {
        let stranger = ActorUri::parse(&format!("https://idp.eve.test/users/eve_{i:05}")).unwrap();
        w.graph.block(&w.alice, &stranger).await.unwrap();
    }

    let refused = w.block.execute(w.alice.id, w.bob.actor_uri.clone()).await;

    assert!(
        matches!(refused, Err(SocialError::BlockListFull)),
        "{refused:?}"
    );
    assert!(
        w.graph
            .between(w.alice.id, &w.bob.actor_uri)
            .await
            .unwrap()
            .is_some()
    );
    assert!(w.notifier.sent().is_empty());
    assert!(w.notifier.blocks_updated().is_empty());
}

#[tokio::test]
async fn unblocking_lifts_the_block_and_restores_nothing() {
    let w = world();
    let request = w
        .graph
        .record_local_request(&w.bob, &w.alice)
        .await
        .unwrap()
        .target_side;
    w.graph.accept(&request, &w.alice).await.unwrap();
    w.block
        .execute(w.alice.id, w.bob.actor_uri.clone())
        .await
        .unwrap();

    w.unblock
        .execute(w.alice.id, w.bob.actor_uri.clone())
        .await
        .unwrap();

    assert!(w.list.execute(w.alice.id).await.unwrap().is_empty());
    assert!(
        w.graph.friends(w.alice.id).await.unwrap().is_empty(),
        "either side must ask again"
    );
}

#[tokio::test]
async fn unblocking_an_actor_not_blocked_is_refused_and_tells_no_one() {
    let w = world();

    let refused = w.unblock.execute(w.alice.id, w.bob.actor_uri.clone()).await;

    assert!(
        matches!(refused, Err(SocialError::NotBlocked)),
        "{refused:?}"
    );
    assert!(w.notifier.blocks_updated().is_empty());
}
