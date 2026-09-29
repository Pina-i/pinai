use std::sync::Arc;

use domain::identity::testing::{InMemoryAccounts, InMemoryRemoteActors, account, remote_actor};
use domain::identity::{Account, RemoteActor};
use domain::social::testing::{
    InMemorySocialGraph, Notice, RecordingSocialFederation, RecordingSocialNotifier, Sent,
};
use domain::social::{Direction, FriendshipStatus, SocialGraph};

use super::*;

struct World {
    bob: Account,
    remote_carol: RemoteActor,
    graph: Arc<InMemorySocialGraph>,
    notifier: Arc<RecordingSocialNotifier>,
    federation: Arc<RecordingSocialFederation>,
    receive: ReceiveFollow,
}

fn world() -> World {
    let bob = account("bob");
    let mut remote_carol = remote_actor("carol_k2m9x@idp.carol.test");
    remote_carol.display_name = Some("Carol".to_owned());
    let graph = Arc::new(InMemorySocialGraph::default());
    let notifier = Arc::new(RecordingSocialNotifier::default());
    let federation = Arc::new(RecordingSocialFederation::default());
    let receive = ReceiveFollow::new(
        Arc::new(InMemoryAccounts::with([bob.clone()])),
        Arc::new(InMemoryRemoteActors::with([remote_carol.clone()])),
        graph.clone(),
        notifier.clone(),
        federation.clone(),
    );
    World {
        bob,
        remote_carol,
        graph,
        notifier,
        federation,
        receive,
    }
}

#[tokio::test]
async fn a_remote_follow_is_recorded_and_announced_to_the_recipient() {
    let w = world();

    w.receive
        .execute(w.bob.id, w.remote_carol.actor_uri.clone())
        .await
        .unwrap();

    let side = w
        .graph
        .between(w.bob.id, &w.remote_carol.actor_uri)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (side.status, side.direction),
        (FriendshipStatus::Pending, Direction::Incoming)
    );
    let sent = w.notifier.sent();
    let [(Notice::FriendRequest, to, event)] = sent.as_slice() else {
        panic!("one friend_request expected, got {sent:?}");
    };
    assert_eq!((*to, event.friendship), (w.bob.id, side.id));
    assert_eq!(
        (event.username.as_str(), event.display_name.as_deref()),
        ("carol_k2m9x", Some("Carol"))
    );
}

#[tokio::test]
async fn a_redelivered_follow_leaves_one_request() {
    let w = world();

    w.receive
        .execute(w.bob.id, w.remote_carol.actor_uri.clone())
        .await
        .unwrap();
    w.receive
        .execute(w.bob.id, w.remote_carol.actor_uri.clone())
        .await
        .unwrap();

    assert_eq!(w.graph.incoming_requests(w.bob.id).await.unwrap().len(), 1);
}

#[tokio::test]
async fn a_follow_for_an_accepted_friendship_is_answered_again_without_reopening_it() {
    let w = world();
    w.receive
        .execute(w.bob.id, w.remote_carol.actor_uri.clone())
        .await
        .unwrap();
    let request = w
        .graph
        .between(w.bob.id, &w.remote_carol.actor_uri)
        .await
        .unwrap()
        .unwrap();
    let dm = w.graph.accept(&request, &w.bob).await.unwrap();

    w.receive
        .execute(w.bob.id, w.remote_carol.actor_uri.clone())
        .await
        .unwrap();

    let side = w
        .graph
        .between(w.bob.id, &w.remote_carol.actor_uri)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(side.status, FriendshipStatus::Accepted);
    assert_eq!(
        w.federation.sent(),
        vec![Sent::Accept {
            from: w.bob.actor_uri.clone(),
            to: w.remote_carol.actor_uri.clone(),
            request: request.id,
            conversation: dm,
        }]
    );
}

#[tokio::test]
async fn a_follow_from_a_local_account_records_both_sides() {
    let (alice, bob) = (account("alice"), account("bob"));
    let graph = Arc::new(InMemorySocialGraph::default());
    let notifier = Arc::new(RecordingSocialNotifier::default());
    let receive = ReceiveFollow::new(
        Arc::new(InMemoryAccounts::with([alice.clone(), bob.clone()])),
        Arc::new(InMemoryRemoteActors::default()),
        graph.clone(),
        notifier.clone(),
        Arc::new(RecordingSocialFederation::default()),
    );

    receive
        .execute(bob.id, alice.actor_uri.clone())
        .await
        .unwrap();

    let alice_side = graph
        .between(alice.id, &bob.actor_uri)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(alice_side.direction, Direction::Outgoing);
    assert_eq!(notifier.sent().len(), 1);
}
