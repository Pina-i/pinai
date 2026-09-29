use domain::identity::{Accounts, ActorUri, Handle, RemoteActors, RemoteActorsError};
use federation_transport::UrlPolicy;
use infrastructure::federation::FederatedRemoteActors;
use infrastructure::postgres::PgAccounts;
use sqlx::PgPool;

use super::an_account;

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn an_account_is_found_by_id_handle_and_actor_uri(pool: PgPool) {
    let alice = an_account(&pool, "alice").await;
    let accounts = PgAccounts::new(pool);

    let handle = Handle::parse(&alice.username).unwrap();
    assert_eq!(
        accounts.find(alice.id).await.unwrap().as_ref(),
        Some(&alice)
    );
    assert_eq!(
        accounts.find_by_handle(&handle).await.unwrap().as_ref(),
        Some(&alice)
    );
    assert_eq!(
        accounts.find_by_uri(&alice.actor_uri).await.unwrap(),
        Some(alice)
    );
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn an_account_without_an_actor_uri_is_not_addressable(pool: PgPool) {
    let id = super::a_user(&pool).await;

    assert!(PgAccounts::new(pool).find(id).await.is_err());
}

// Port 9 (discard) refuses connections: the peer is unreachable, as a down instance is.
const UNREACHABLE: &str = "http://127.0.0.1:9/users/dave_k2m9x";

fn remote_actors(pool: PgPool) -> FederatedRemoteActors {
    FederatedRemoteActors::new(
        pool,
        "http".to_owned(),
        UrlPolicy::from_issuer("http://localhost:8080"),
    )
}

async fn a_cached_actor(pool: &PgPool, uri: &str, inbox: Option<&str>) {
    sqlx::query(
        "INSERT INTO remote_actors (actor_uri, inbox_url, instance, display_name) \
         VALUES ($1, $2, '127.0.0.1:9', 'dave')",
    )
    .bind(uri)
    .bind(inbox)
    .execute(pool)
    .await
    .unwrap();
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_cached_remote_actor_is_found_with_its_inbox(pool: PgPool) {
    a_cached_actor(&pool, UNREACHABLE, Some("http://127.0.0.1:9/shared-inbox")).await;

    let dave = remote_actors(pool)
        .find(&ActorUri::parse(UNREACHABLE).unwrap())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(dave.inbox.as_str(), "http://127.0.0.1:9/shared-inbox");
    assert_eq!(dave.display_name.as_deref(), Some("dave"));
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn an_actor_cached_without_an_inbox_is_reached_at_the_conventional_one(pool: PgPool) {
    a_cached_actor(&pool, UNREACHABLE, None).await;

    let dave = remote_actors(pool)
        .find(&ActorUri::parse(UNREACHABLE).unwrap())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(dave.inbox.as_str(), format!("{UNREACHABLE}/inbox"));
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn discovering_an_unreachable_cached_actor_keeps_what_was_known_of_it(pool: PgPool) {
    a_cached_actor(&pool, UNREACHABLE, Some("http://127.0.0.1:9/shared-inbox")).await;
    let actors = remote_actors(pool);

    let dave = actors
        .discover(&ActorUri::parse(UNREACHABLE).unwrap())
        .await
        .unwrap();

    assert_eq!(dave.inbox.as_str(), "http://127.0.0.1:9/shared-inbox");
    assert_eq!(dave.display_name.as_deref(), Some("dave"));
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn an_actor_is_discovered_even_when_its_instance_is_unreachable(pool: PgPool) {
    let actors = remote_actors(pool);
    let dave = ActorUri::parse(UNREACHABLE).unwrap();

    let discovered = actors.discover(&dave).await.unwrap();

    assert_eq!(discovered.inbox.as_str(), format!("{UNREACHABLE}/inbox"));
    assert_eq!(actors.find(&dave).await.unwrap(), Some(discovered));
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_uri_naming_no_account_cannot_be_discovered(pool: PgPool) {
    let not_an_account = ActorUri::parse("http://127.0.0.1:9/groups/7").unwrap();

    let refused = remote_actors(pool).discover(&not_an_account).await;

    assert!(
        matches!(refused, Err(RemoteActorsError::NotFound)),
        "{refused:?}"
    );
}
