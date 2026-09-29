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
    remote_carol: RemoteActor,
    graph: Arc<InMemorySocialGraph>,
    notifier: Arc<RecordingSocialNotifier>,
    federation: Arc<RecordingSocialFederation>,
    presence: Arc<RecordingFriendPresence>,
    accept: AcceptFriendRequest,
}

fn world() -> World {
    let (alice, bob) = (account("alice"), account("bob"));
    let remote_carol = remote_actor("carol_k2m9x@idp.carol.test");
    let graph = Arc::new(InMemorySocialGraph::default());
    let notifier = Arc::new(RecordingSocialNotifier::default());
    let federation = Arc::new(RecordingSocialFederation::default());
    let presence = Arc::new(RecordingFriendPresence::default());
    let accept = AcceptFriendRequest::new(
        Arc::new(InMemoryAccounts::with([alice.clone(), bob.clone()])),
        Arc::new(InMemoryRemoteActors::with([remote_carol.clone()])),
        graph.clone(),
        notifier.clone(),
        federation.clone(),
        presence.clone(),
    );
    World {
        alice,
        bob,
        remote_carol,
        graph,
        notifier,
        federation,
        presence,
        accept,
    }
}

#[tokio::test]
async fn accepting_a_local_request_befriends_both_and_tells_the_requester() {
    let w = world();
    let request = w
        .graph
        .record_local_request(&w.alice, &w.bob)
        .await
        .unwrap()
        .target_side;

    w.accept.execute(w.bob.id, request.id).await.unwrap();

    let alice_side = w
        .graph
        .between(w.alice.id, &w.bob.actor_uri)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(alice_side.status, FriendshipStatus::Accepted);
    let sent = w.notifier.sent();
    assert_eq!(sent.len(), 1);
    let (notice, to, event) = &sent[0];
    assert_eq!((*notice, *to), (Notice::FriendAccepted, w.alice.id));
    assert_eq!(event.friendship, request.id);
    assert_eq!(event.actor_uri, w.bob.actor_uri);
    assert!(
        event.conversation.is_some(),
        "the requester is told which DM to open"
    );
    assert_eq!(w.presence.watched(), vec![w.alice.actor_uri.clone()]);
}

fn incoming_from(owner: &Account, remote: &RemoteActor) -> Friendship {
    Friendship {
        id: FriendshipId::generate(),
        owner: owner.id,
        friend: remote.actor_uri.clone(),
        status: FriendshipStatus::Pending,
        direction: Direction::Incoming,
    }
}

#[tokio::test]
async fn accepting_a_remote_request_answers_its_instance_with_the_dm() {
    let w = world();
    let request = incoming_from(&w.bob, &w.remote_carol);
    w.graph.insert(request.clone());

    w.accept.execute(w.bob.id, request.id).await.unwrap();

    let sent = w.federation.sent();
    let [
        Sent::Accept {
            from,
            to,
            request: answered,
            ..
        },
    ] = sent.as_slice()
    else {
        panic!("one Accept expected, got {sent:?}");
    };
    assert_eq!(
        (from, to, *answered),
        (&w.bob.actor_uri, &w.remote_carol.actor_uri, request.id)
    );
    assert!(
        w.notifier.sent().is_empty(),
        "the remote requester is told by its own IdP"
    );
    assert_eq!(w.presence.watched(), vec![w.remote_carol.actor_uri.clone()]);
}

#[tokio::test]
async fn only_a_pending_request_the_caller_received_can_be_accepted() {
    let w = world();
    let sent_by_alice = w
        .graph
        .record_local_request(&w.alice, &w.bob)
        .await
        .unwrap();

    let unknown = w.accept.execute(w.bob.id, FriendshipId::generate()).await;
    let someone_elses = w
        .accept
        .execute(w.alice.id, sent_by_alice.target_side.id)
        .await;
    let own_request = w
        .accept
        .execute(w.alice.id, sent_by_alice.requester_side.id)
        .await;

    assert!(
        matches!(unknown, Err(SocialError::RequestNotFound)),
        "{unknown:?}"
    );
    assert!(
        matches!(someone_elses, Err(SocialError::NotYours)),
        "{someone_elses:?}"
    );
    assert!(
        matches!(own_request, Err(SocialError::NotAnIncomingRequest)),
        "{own_request:?}"
    );
    assert!(w.notifier.sent().is_empty());
}
