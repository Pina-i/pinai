use std::sync::Arc;

use domain::identity::testing::{InMemoryAccounts, InMemoryRemoteActors, account, remote_actor};
use domain::identity::{Account, FederatedAddress, Handle, Recipient, RemoteActor};
use domain::social::testing::{
    BLOCKED, InMemorySocialGraph, KEPT_OUT_BY_THE_SETTING, Notice, RecordingSocialFederation,
    RecordingSocialNotifier, Sent, StubReachability,
};
use domain::social::{Direction, FriendshipEvent, FriendshipStatus, SocialGraph};

use super::*;

struct World {
    alice: Account,
    bob: Account,
    remote_carol: RemoteActor,
    graph: Arc<InMemorySocialGraph>,
    notifier: Arc<RecordingSocialNotifier>,
    federation: Arc<RecordingSocialFederation>,
    reach: Arc<StubReachability>,
    send: SendFriendRequest,
}

fn world() -> World {
    let (alice, bob) = (account("alice"), account("bob"));
    let remote_carol = remote_actor("carol_k2m9x@idp.carol.test");
    let graph = Arc::new(InMemorySocialGraph::default());
    let notifier = Arc::new(RecordingSocialNotifier::default());
    let federation = Arc::new(RecordingSocialFederation::default());
    let reach = Arc::new(StubReachability::default());
    let send = SendFriendRequest::new(
        Arc::new(InMemoryAccounts::with([alice.clone(), bob.clone()])),
        Arc::new(InMemoryRemoteActors::with([remote_carol.clone()])),
        graph.clone(),
        reach.clone(),
        notifier.clone(),
        federation.clone(),
    );
    World {
        alice,
        bob,
        remote_carol,
        graph,
        notifier,
        federation,
        reach,
        send,
    }
}

fn local(account: &Account) -> Recipient {
    Recipient::Local(Handle::parse(&account.username).unwrap())
}

fn remote(address: &str) -> Recipient {
    Recipient::Remote(FederatedAddress::parse(address).unwrap())
}

#[tokio::test]
async fn a_request_to_a_local_account_is_recorded_and_announced_to_it() {
    let w = world();

    let sent = w.send.execute(w.alice.id, local(&w.bob)).await.unwrap();

    assert_eq!((sent.owner, &sent.friend), (w.alice.id, &w.bob.actor_uri));
    assert_eq!(
        (sent.status, sent.direction),
        (FriendshipStatus::Pending, Direction::Outgoing)
    );
    let bob_side = w
        .graph
        .between(w.bob.id, &w.alice.actor_uri)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        w.notifier.sent(),
        vec![(
            Notice::FriendRequest,
            w.bob.id,
            FriendshipEvent {
                friendship: bob_side.id,
                actor_uri: w.alice.actor_uri.clone(),
                username: w.alice.username.clone(),
                display_name: w.alice.display_name.clone(),
                conversation: None,
            }
        )]
    );
}

#[tokio::test]
async fn a_request_to_an_unknown_local_name_finds_no_user() {
    let w = world();

    let refused = w
        .send
        .execute(
            w.alice.id,
            Recipient::Local(Handle::parse("nobody_t3st0").unwrap()),
        )
        .await;

    assert!(
        matches!(refused, Err(SocialError::UserNotFound)),
        "{refused:?}"
    );
    assert!(w.notifier.sent().is_empty());
}

#[tokio::test]
async fn a_request_to_oneself_is_refused() {
    let w = world();

    let refused = w.send.execute(w.alice.id, local(&w.alice)).await;

    assert!(
        matches!(refused, Err(SocialError::SelfRequest)),
        "{refused:?}"
    );
    assert!(
        w.graph
            .between(w.alice.id, &w.alice.actor_uri)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn a_request_to_a_friend_is_refused() {
    let w = world();
    w.graph.insert(domain::social::Friendship {
        id: domain::FriendshipId::generate(),
        owner: w.alice.id,
        friend: w.bob.actor_uri.clone(),
        status: FriendshipStatus::Accepted,
        direction: Direction::Outgoing,
    });

    let refused = w.send.execute(w.alice.id, local(&w.bob)).await;

    assert!(
        matches!(refused, Err(SocialError::AlreadyFriends)),
        "{refused:?}"
    );
    assert!(w.notifier.sent().is_empty());
}

#[tokio::test]
async fn a_request_to_a_remote_account_records_its_side_and_sends_a_follow() {
    let w = world();

    let sent = w
        .send
        .execute(w.alice.id, remote("carol_k2m9x@idp.carol.test"))
        .await
        .unwrap();

    assert_eq!(
        (sent.owner, &sent.friend),
        (w.alice.id, &w.remote_carol.actor_uri)
    );
    assert_eq!(
        (sent.status, sent.direction),
        (FriendshipStatus::Pending, Direction::Outgoing)
    );
    assert_eq!(
        w.federation.sent(),
        vec![Sent::Follow {
            from: w.alice.actor_uri.clone(),
            to: w.remote_carol.actor_uri.clone()
        }]
    );
    assert!(
        w.notifier.sent().is_empty(),
        "the remote side is told by its own IdP"
    );
}

#[tokio::test]
async fn a_request_to_an_unknown_remote_address_finds_no_user() {
    let w = world();

    let refused = w
        .send
        .execute(w.alice.id, remote("nobody_k2m9x@idp.carol.test"))
        .await;

    assert!(
        matches!(refused, Err(SocialError::UserNotFound)),
        "{refused:?}"
    );
    assert!(w.federation.sent().is_empty());
}

#[tokio::test]
async fn a_request_to_someone_the_caller_blocked_is_refused() {
    let w = world();
    w.reach.set(w.alice.id, &w.bob.actor_uri, BLOCKED);
    w.reach.set(w.alice.id, &w.remote_carol.actor_uri, BLOCKED);

    for to in [local(&w.bob), remote("carol_k2m9x@idp.carol.test")] {
        let refused = w.send.execute(w.alice.id, to).await;

        assert!(
            matches!(refused, Err(SocialError::YouBlocked)),
            "{refused:?}"
        );
    }
    assert_eq!(
        w.graph.between(w.alice.id, &w.bob.actor_uri).await.unwrap(),
        None
    );
    assert!(w.notifier.sent().is_empty());
    assert!(w.federation.sent().is_empty());
}

/// To Alice, a request Bob's block keeps out looks like any request still unanswered.
#[tokio::test]
async fn a_request_to_someone_who_blocked_the_caller_stays_unanswered() {
    let w = world();
    w.reach.set(w.bob.id, &w.alice.actor_uri, BLOCKED);

    let sent = w.send.execute(w.alice.id, local(&w.bob)).await.unwrap();

    assert_eq!(
        (sent.owner, sent.status, sent.direction),
        (w.alice.id, FriendshipStatus::Pending, Direction::Outgoing)
    );
    assert_eq!(
        w.graph.between(w.alice.id, &w.bob.actor_uri).await.unwrap(),
        Some(sent)
    );
    assert_eq!(
        w.graph.between(w.bob.id, &w.alice.actor_uri).await.unwrap(),
        None
    );
    assert!(w.notifier.sent().is_empty());
}

#[tokio::test]
async fn the_contact_setting_never_keeps_a_request_out() {
    let w = world();
    w.reach
        .set(w.bob.id, &w.alice.actor_uri, KEPT_OUT_BY_THE_SETTING);

    w.send.execute(w.alice.id, local(&w.bob)).await.unwrap();

    assert!(
        w.graph
            .between(w.bob.id, &w.alice.actor_uri)
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(w.notifier.sent().len(), 1);
}

#[tokio::test]
async fn a_request_to_an_instance_that_does_not_answer_is_refused_and_records_nothing() {
    let alice = account("alice");
    let graph = Arc::new(InMemorySocialGraph::default());
    let federation = Arc::new(RecordingSocialFederation::default());
    let send = SendFriendRequest::new(
        Arc::new(InMemoryAccounts::with([alice.clone()])),
        Arc::new(InMemoryRemoteActors::default().and_down("idp.down.test")),
        graph.clone(),
        Arc::new(StubReachability::default()),
        Arc::new(RecordingSocialNotifier::default()),
        federation.clone(),
    );

    let refused = send
        .execute(alice.id, remote("dave_k2m9x@idp.down.test"))
        .await;

    assert!(
        matches!(refused, Err(SocialError::PeerUnavailable(_))),
        "{refused:?}"
    );
    assert!(federation.sent().is_empty());
}
