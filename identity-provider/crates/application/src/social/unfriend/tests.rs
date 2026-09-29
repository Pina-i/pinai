use std::sync::Arc;

use domain::FriendshipId;
use domain::identity::testing::{InMemoryAccounts, InMemoryRemoteActors, account, remote_actor};
use domain::identity::{Account, RemoteActor};
use domain::social::testing::{
    InMemorySocialGraph, Notice, RecordingFriendPresence, RecordingSocialFederation,
    RecordingSocialNotifier, Sent,
};
use domain::social::{Direction, Friendship, FriendshipStatus, SocialGraph};

use super::*;

struct World {
    alice: Account,
    bob: Account,
    pierre: Account,
    remote_carol: RemoteActor,
    graph: Arc<InMemorySocialGraph>,
    notifier: Arc<RecordingSocialNotifier>,
    federation: Arc<RecordingSocialFederation>,
    presence: Arc<RecordingFriendPresence>,
    unfriend: Unfriend,
}

fn world() -> World {
    let (alice, bob, pierre) = (account("alice"), account("bob"), account("pierre"));
    let remote_carol = remote_actor("carol_k2m9x@idp.carol.test");
    let graph = Arc::new(InMemorySocialGraph::default());
    let notifier = Arc::new(RecordingSocialNotifier::default());
    let federation = Arc::new(RecordingSocialFederation::default());
    let presence = Arc::new(RecordingFriendPresence::default());
    let unfriend = Unfriend::new(
        Arc::new(InMemoryAccounts::with([
            alice.clone(),
            bob.clone(),
            pierre.clone(),
        ])),
        Arc::new(InMemoryRemoteActors::with([remote_carol.clone()])),
        graph.clone(),
        notifier.clone(),
        federation.clone(),
        presence.clone(),
    );
    World {
        alice,
        bob,
        pierre,
        remote_carol,
        graph,
        notifier,
        federation,
        presence,
        unfriend,
    }
}

async fn befriend(w: &World, a: &Account, b: &Account) -> FriendshipId {
    let request = w
        .graph
        .record_local_request(a, b)
        .await
        .unwrap()
        .target_side;
    w.graph.accept(&request, b).await.unwrap();
    request.id
}

fn accepted(owner: &Account, remote: &RemoteActor) -> Friendship {
    Friendship {
        id: FriendshipId::generate(),
        owner: owner.id,
        friend: remote.actor_uri.clone(),
        status: FriendshipStatus::Accepted,
        direction: Direction::Outgoing,
    }
}

#[tokio::test]
async fn unfriending_a_local_friend_tells_their_clients_to_drop_it() {
    let w = world();
    let bob_side = befriend(&w, &w.alice, &w.bob).await;

    w.unfriend
        .execute(w.alice.id, w.bob.actor_uri.clone())
        .await
        .unwrap();

    let sent = w.notifier.sent();
    assert_eq!(sent.len(), 1);
    let (notice, to, event) = &sent[0];
    assert_eq!(
        (*notice, *to, event.friendship),
        (Notice::FriendRemoved, w.bob.id, bob_side)
    );
    assert_eq!(event.actor_uri, w.alice.actor_uri);
}

#[tokio::test]
async fn unfriending_a_remote_friend_undoes_the_follow_and_releases_their_presence() {
    let w = world();
    w.graph.insert(accepted(&w.alice, &w.remote_carol));

    w.unfriend
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
async fn a_remote_friends_presence_stays_watched_while_someone_else_befriends_them() {
    let w = world();
    w.graph.insert(accepted(&w.alice, &w.remote_carol));
    w.graph.insert(accepted(&w.pierre, &w.remote_carol));

    w.unfriend
        .execute(w.alice.id, w.remote_carol.actor_uri.clone())
        .await
        .unwrap();

    assert!(w.presence.released().is_empty());
}

#[tokio::test]
async fn unfriending_someone_who_is_no_friend_is_refused() {
    let w = world();

    let refused = w
        .unfriend
        .execute(w.alice.id, w.bob.actor_uri.clone())
        .await;

    assert!(
        matches!(refused, Err(SocialError::NotFriends)),
        "{refused:?}"
    );
}
