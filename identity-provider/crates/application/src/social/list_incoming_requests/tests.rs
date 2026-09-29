use std::sync::Arc;

use domain::FriendshipId;
use domain::identity::testing::{InMemoryAccounts, InMemoryRemoteActors, account, remote_actor};
use domain::social::testing::InMemorySocialGraph;
use domain::social::{Direction, Friendship, FriendshipStatus, SocialGraph};

use super::*;

#[tokio::test]
async fn each_request_carries_its_requesters_name() {
    let (alice, bob) = (account("alice"), account("bob"));
    let mut carol = remote_actor("carol_k2m9x@idp.carol.test");
    carol.display_name = Some("Carol".to_owned());
    let graph = Arc::new(InMemorySocialGraph::default());
    let from_alice = graph
        .record_local_request(&alice, &bob)
        .await
        .unwrap()
        .target_side;
    let from_carol = Friendship {
        id: FriendshipId::generate(),
        owner: bob.id,
        friend: carol.actor_uri.clone(),
        status: FriendshipStatus::Pending,
        direction: Direction::Incoming,
    };
    graph.insert(from_carol.clone());
    let list = ListIncomingRequests::new(
        Arc::new(InMemoryAccounts::with([alice.clone(), bob.clone()])),
        Arc::new(InMemoryRemoteActors::with([carol.clone()])),
        graph,
    );

    let incoming = list.execute(bob.id).await.unwrap();

    assert_eq!(
        incoming,
        vec![
            IncomingRequest {
                friendship: from_carol.id,
                actor_uri: carol.actor_uri.clone(),
                username: "carol_k2m9x".to_owned(),
                display_name: Some("Carol".to_owned()),
            },
            IncomingRequest {
                friendship: from_alice.id,
                actor_uri: alice.actor_uri.clone(),
                username: alice.username.clone(),
                display_name: alice.display_name.clone(),
            },
        ]
    );
}
