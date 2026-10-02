use std::sync::Arc;

use domain::FriendshipId;
use domain::identity::testing::{InMemoryAccounts, InMemoryRemoteActors, account, remote_actor};
use domain::identity::{Account, RemoteActor};
use domain::profile::testing::{
    InMemoryProfiles, ProfileSeeds, RecordingProfileFederation, own_profile,
};
use domain::profile::{OwnProfile, Pronouns};
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
    /// What `bob` shows.
    bobs: OwnProfile,
    profile_federation: Arc<RecordingProfileFederation>,
    accept: AcceptFriendRequest,
}

async fn world() -> World {
    let (alice, bob) = (account("alice"), account("bob"));
    let remote_carol = remote_actor("carol_k2m9x@idp.carol.test");
    let graph = Arc::new(InMemorySocialGraph::default());
    let notifier = Arc::new(RecordingSocialNotifier::default());
    let federation = Arc::new(RecordingSocialFederation::default());
    let presence = Arc::new(RecordingFriendPresence::default());
    let profiles = Arc::new(InMemoryProfiles::default());
    let bobs = OwnProfile {
        id: bob.id,
        pronouns: Some(Pronouns::He),
        bio: Some("kia ora".to_owned()),
        ..own_profile("bob")
    };
    profiles.sign_up(&bobs).await;
    let profile_federation = Arc::new(RecordingProfileFederation::default());
    let accept = AcceptFriendRequest::new(
        Arc::new(InMemoryAccounts::with([alice.clone(), bob.clone()])),
        Arc::new(InMemoryRemoteActors::with([remote_carol.clone()])),
        graph.clone(),
        notifier.clone(),
        federation.clone(),
        presence.clone(),
        profiles,
        profile_federation.clone(),
    );
    World {
        alice,
        bob,
        remote_carol,
        graph,
        notifier,
        federation,
        presence,
        bobs,
        profile_federation,
        accept,
    }
}

#[tokio::test]
async fn accepting_a_local_request_befriends_both_and_tells_the_requester() {
    let w = world().await;
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
    assert_eq!(
        w.profile_federation.sent(),
        [],
        "an account here reads the profile itself"
    );
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
    let w = world().await;
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
async fn accepting_a_remote_request_sends_the_new_friend_the_profile_the_caller_shows() {
    let w = world().await;
    let request = incoming_from(&w.bob, &w.remote_carol);
    w.graph.insert(request.clone());

    w.accept.execute(w.bob.id, request.id).await.unwrap();

    assert_eq!(
        w.profile_federation.sent(),
        [(w.bobs.public().unwrap(), w.remote_carol.actor_uri.clone())]
    );
}

#[tokio::test]
async fn only_a_pending_request_the_caller_received_can_be_accepted() {
    let w = world().await;
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
