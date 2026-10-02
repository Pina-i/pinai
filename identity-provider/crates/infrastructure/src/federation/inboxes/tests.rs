use domain::identity::RemoteActor;
use domain::identity::testing::{InMemoryRemoteActors, remote_actor};

use super::*;

fn inboxes(remote_actors: InMemoryRemoteActors) -> (Inboxes, Arc<InMemoryRemoteActors>) {
    let remote_actors = Arc::new(remote_actors);
    let origin = InstanceOrigin::parse("https://idp.alice.test").unwrap();
    (Inboxes::new(origin, remote_actors.clone()), remote_actors)
}

fn carol() -> RemoteActor {
    remote_actor("carol_k2m9x@idp.carol.test")
}

#[tokio::test]
async fn a_cached_actor_is_reached_at_its_inbox_without_asking_anyone() {
    let (inboxes, remote_actors) = inboxes(InMemoryRemoteActors::with([carol()]));
    let mut lookups = 0;

    let inbox = inboxes.of(&carol().actor_uri, &mut lookups).await;

    assert_eq!(inbox, Some(carol().inbox));
    assert_eq!(remote_actors.lookups(), 0);
}

#[tokio::test]
async fn an_actor_never_met_is_resolved_on_its_instance_once() {
    let (inboxes, remote_actors) = inboxes(InMemoryRemoteActors::default().and_uncached([carol()]));
    let mut lookups = LOOKUPS_PER_SEND;

    let first = inboxes.of(&carol().actor_uri, &mut lookups).await;
    let again = inboxes.of(&carol().actor_uri, &mut lookups).await;

    assert_eq!((first, again), (Some(carol().inbox), Some(carol().inbox)));
    assert_eq!(remote_actors.lookups(), 1, "cached after the first");
    assert_eq!(lookups, LOOKUPS_PER_SEND - 1);
}

#[tokio::test]
async fn an_account_of_this_instance_is_never_looked_up() {
    let (inboxes, remote_actors) = inboxes(InMemoryRemoteActors::default());
    let alice = ActorUri::parse("https://idp.alice.test/users/alice_t3st0").unwrap();

    assert_eq!(inboxes.of(&alice, &mut 1).await, None);
    assert_eq!(remote_actors.lookups(), 0);
}

#[tokio::test]
async fn an_actor_that_could_not_be_resolved_is_left_alone_for_a_while() {
    let dave = remote_actor("dave_k2m9x@idp.dave.test");
    for remote_actors in [
        InMemoryRemoteActors::default(),
        InMemoryRemoteActors::default().and_down("idp.dave.test"),
    ] {
        let (inboxes, remote_actors) = inboxes(remote_actors);

        assert_eq!(inboxes.of(&dave.actor_uri, &mut 5).await, None);
        assert_eq!(inboxes.of(&dave.actor_uri, &mut 5).await, None);

        assert_eq!(remote_actors.lookups(), 1);
    }
}

#[tokio::test]
async fn an_unresolved_actor_is_asked_for_again_once_the_while_is_over() {
    let dave = remote_actor("dave_k2m9x@idp.dave.test");
    let (inboxes, remote_actors) = inboxes(InMemoryRemoteActors::default());
    let inboxes = Inboxes {
        retry_after: Duration::ZERO,
        ..inboxes
    };

    inboxes.of(&dave.actor_uri, &mut 5).await;
    inboxes.of(&dave.actor_uri, &mut 5).await;

    assert_eq!(remote_actors.lookups(), 2);
}

#[tokio::test]
async fn a_send_asks_no_more_instances_than_its_budget() {
    let dave = remote_actor("dave_k2m9x@idp.dave.test");
    let (inboxes, remote_actors) =
        inboxes(InMemoryRemoteActors::default().and_uncached([carol(), dave.clone()]));
    let mut lookups = 1;

    let first = inboxes.of(&carol().actor_uri, &mut lookups).await;
    let second = inboxes.of(&dave.actor_uri, &mut lookups).await;

    assert_eq!((first, second), (Some(carol().inbox), None));
    assert_eq!(remote_actors.lookups(), 1);
    assert_eq!(
        inboxes.of(&dave.actor_uri, &mut 1).await,
        Some(dave.inbox),
        "left for a later send, not marked unresolved"
    );
}

#[tokio::test]
async fn an_answer_naming_another_actor_is_no_inbox_for_this_one() {
    // Same address, other actor: what their instance names is not this URI.
    let named = RemoteActor {
        actor_uri: ActorUri::parse("http://idp.carol.test/users/carol_k2m9x").unwrap(),
        ..carol()
    };
    let (inboxes, remote_actors) = inboxes(InMemoryRemoteActors::default().and_uncached([named]));

    assert_eq!(inboxes.of(&carol().actor_uri, &mut 5).await, None);
    assert_eq!(inboxes.of(&carol().actor_uri, &mut 5).await, None);
    assert_eq!(remote_actors.lookups(), 1, "left alone after the first");
}
