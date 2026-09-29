use std::sync::Arc;

use domain::identity::testing::{InMemoryAccounts, InMemoryRemoteActors, account, remote_actor};
use domain::identity::{Account, FederatedAddress, Handle, Recipient, RemoteActor};
use domain::social::testing::{
    InMemorySocialGraph, Notice, RecordingSocialFederation, RecordingSocialNotifier, Sent,
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
    send: SendFriendRequest,
}

fn world() -> World {
    let (alice, bob) = (account("alice"), account("bob"));
    let remote_carol = remote_actor("carol_k2m9x@idp.carol.test");
    let graph = Arc::new(InMemorySocialGraph::default());
    let notifier = Arc::new(RecordingSocialNotifier::default());
    let federation = Arc::new(RecordingSocialFederation::default());
    let send = SendFriendRequest::new(
        Arc::new(InMemoryAccounts::with([alice.clone(), bob.clone()])),
        Arc::new(InMemoryRemoteActors::with([remote_carol.clone()])),
        graph.clone(),
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
