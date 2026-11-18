use domain::identity::testing::{InMemoryRemoteActors, account, remote_actor};
use domain::identity::{
    ActorUri, FederatedAddress, Handle, RemoteActor, RemoteActors, RemoteActorsError,
};
use domain::social::testing::people::{Admission, InMemoryPeopleSearch, PeopleSeeds};
use domain::social::{Direction, FriendshipStatus, Standing};

use super::*;

fn remote(address: &str) -> Recipient {
    Recipient::Remote(FederatedAddress::parse(address).unwrap())
}

#[tokio::test]
async fn an_account_here_is_answered_with_the_callers_ties() {
    let people = Arc::new(InMemoryPeopleSearch::default());
    let (alice, hoku) = (account("alice"), account("hoku"));
    people.sign_up(&alice, Admission::Confirmed).await;
    people.sign_up(&hoku, Admission::Confirmed).await;
    people
        .befriend(
            alice.id,
            &hoku.actor_uri,
            FriendshipStatus::Accepted,
            Direction::Outgoing,
        )
        .await;
    let look_up = LookUpAddress::new(people, Arc::new(InMemoryRemoteActors::default()));

    let found = look_up
        .execute(
            alice.id,
            &Recipient::Local(Handle::parse("hoku_t3st0").unwrap()),
        )
        .await
        .unwrap()
        .expect("hoku");

    assert_eq!(found.actor, hoku.actor_uri);
    assert_eq!(found.ties.standing(), Standing::Friend);
}

#[tokio::test]
async fn an_address_elsewhere_is_asked_of_its_instance_and_remembered() {
    let people = Arc::new(InMemoryPeopleSearch::default());
    let alice = account("alice");
    people.sign_up(&alice, Admission::Confirmed).await;
    let mahealani = RemoteActor {
        display_name: None,
        ..remote_actor("mahealani_q1x8c@reef.chat")
    };
    people
        .befriend(
            alice.id,
            &mahealani.actor_uri,
            FriendshipStatus::Pending,
            Direction::Outgoing,
        )
        .await;
    let remote_actors = Arc::new(InMemoryRemoteActors::default().and_uncached([mahealani.clone()]));
    let look_up = LookUpAddress::new(people, remote_actors.clone());

    let found = look_up
        .execute(alice.id, &remote("@mahealani_q1x8c@reef.chat"))
        .await
        .unwrap()
        .expect("mahealani");

    assert_eq!(found.actor, mahealani.actor_uri);
    assert_eq!(found.address.to_string(), "mahealani_q1x8c@reef.chat");
    assert_eq!(found.display_name, None, "her document gives no name");
    assert_eq!(found.ties.standing(), Standing::RequestSent);
    assert_eq!(remote_actors.lookups(), 1);
    assert_eq!(
        remote_actors.find(&mahealani.actor_uri).await.unwrap(),
        Some(mahealani),
        "remembered"
    );
}

#[tokio::test]
async fn an_account_its_instance_no_longer_knows_is_none_though_cached_here() {
    let alice = account("alice");
    let gone = remote_actor("gone_k2m9x@reef.chat");
    let look_up = LookUpAddress::new(
        Arc::new(InMemoryPeopleSearch::default()),
        Arc::new(InMemoryRemoteActors::default().and_cached_only([gone])),
    );

    let found = look_up
        .execute(alice.id, &remote("gone_k2m9x@reef.chat"))
        .await
        .unwrap();

    assert_eq!(found, None);
}

/// An instance this one may not ask.
struct Refusing;

#[async_trait::async_trait]
impl RemoteActors for Refusing {
    async fn resolve(&self, _: &FederatedAddress) -> Result<RemoteActor, RemoteActorsError> {
        Err(RemoteActorsError::Refused("a private address".to_owned()))
    }

    async fn find(&self, _: &ActorUri) -> Result<Option<RemoteActor>, RemoteActorsError> {
        unreachable!("a lookup never reads the cache")
    }

    async fn discover(&self, _: &ActorUri) -> Result<RemoteActor, RemoteActorsError> {
        unreachable!("a lookup resolves by address")
    }
}

#[tokio::test]
async fn an_instance_that_does_not_answer_or_may_not_be_asked_is_unavailable() {
    let alice = account("alice");
    let people = Arc::new(InMemoryPeopleSearch::default());
    let down = LookUpAddress::new(
        people.clone(),
        Arc::new(InMemoryRemoteActors::default().and_down("reef.chat")),
    );
    let refused = LookUpAddress::new(people, Arc::new(Refusing));

    for look_up in [down, refused] {
        let failed = look_up
            .execute(alice.id, &remote("mahealani_q1x8c@reef.chat"))
            .await;

        assert!(
            matches!(failed, Err(SocialError::PeerUnavailable(_))),
            "{failed:?}"
        );
    }
}

#[tokio::test]
async fn a_cached_account_whose_instance_does_not_answer_is_unavailable_not_its_cached_copy() {
    let alice = account("alice");
    let mahealani = remote_actor("mahealani_q1x8c@reef.chat");
    let remote_actors = InMemoryRemoteActors::with([mahealani.clone()]).and_down("reef.chat");
    assert!(
        remote_actors
            .find(&mahealani.actor_uri)
            .await
            .unwrap()
            .is_some()
    );
    let look_up = LookUpAddress::new(
        Arc::new(InMemoryPeopleSearch::default()),
        Arc::new(remote_actors),
    );

    let failed = look_up
        .execute(alice.id, &remote("mahealani_q1x8c@reef.chat"))
        .await;

    assert!(
        matches!(failed, Err(SocialError::PeerUnavailable(_))),
        "{failed:?}"
    );
}
