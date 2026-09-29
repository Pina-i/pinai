use std::sync::Arc;

use domain::FriendshipId;
use domain::identity::testing::{InMemoryAccounts, InMemoryRemoteActors, account, remote_actor};
use domain::identity::{Account, RemoteActor};
use domain::social::testing::{
    InMemorySocialGraph, RecordingSocialFederation, RecordingSocialNotifier, Sent,
};
use domain::social::{Direction, Friendship, FriendshipStatus, SocialGraph};

use super::*;

struct World {
    alice: Account,
    bob: Account,
    remote_carol: RemoteActor,
    graph: Arc<InMemorySocialGraph>,
    notifier: Arc<RecordingSocialNotifier>,
    federation: Arc<RecordingSocialFederation>,
    decline: DeclineFriendRequest,
}

fn world() -> World {
    let (alice, bob) = (account("alice"), account("bob"));
    let remote_carol = remote_actor("carol_k2m9x@idp.carol.test");
    let graph = Arc::new(InMemorySocialGraph::default());
    let notifier = Arc::new(RecordingSocialNotifier::default());
    let federation = Arc::new(RecordingSocialFederation::default());
    let decline = DeclineFriendRequest::new(
        Arc::new(InMemoryAccounts::with([alice.clone(), bob.clone()])),
        Arc::new(InMemoryRemoteActors::with([remote_carol.clone()])),
        graph.clone(),
        federation.clone(),
    );
    World {
        alice,
        bob,
        remote_carol,
        graph,
        notifier,
        federation,
        decline,
    }
}

#[tokio::test]
async fn declining_a_local_request_removes_it_silently() {
    let w = world();
    let request = w
        .graph
        .record_local_request(&w.alice, &w.bob)
        .await
        .unwrap()
        .target_side;

    w.decline.execute(w.bob.id, request.id).await.unwrap();

    assert_eq!(
        w.graph.between(w.alice.id, &w.bob.actor_uri).await.unwrap(),
        None
    );
    assert!(
        w.notifier.sent().is_empty(),
        "a declined request is never announced"
    );
    assert!(w.federation.sent().is_empty());
}

#[tokio::test]
async fn declining_a_remote_request_tells_its_instance() {
    let w = world();
    let request = Friendship {
        id: FriendshipId::generate(),
        owner: w.bob.id,
        friend: w.remote_carol.actor_uri.clone(),
        status: FriendshipStatus::Pending,
        direction: Direction::Incoming,
    };
    w.graph.insert(request.clone());

    w.decline.execute(w.bob.id, request.id).await.unwrap();

    assert_eq!(
        w.federation.sent(),
        vec![Sent::Reject {
            from: w.bob.actor_uri.clone(),
            to: w.remote_carol.actor_uri.clone(),
            request: request.id,
        }]
    );
}
