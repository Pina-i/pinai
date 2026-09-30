use std::net::SocketAddr;

use domain::identity::{Accounts, ActorUri, Handle, RemoteActors, RemoteActorsError};
use federation_transport::UrlPolicy;
use infrastructure::federation::FederatedRemoteActors;
use infrastructure::postgres::PgAccounts;
use sqlx::PgPool;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

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
async fn a_search_finds_the_handles_holding_the_query(pool: PgPool) {
    let (alice, bob) = (
        an_account(&pool, "alice").await,
        an_account(&pool, "bob").await,
    );
    super::a_user(&pool).await;

    domain::identity::testing::contract::a_search_finds_the_handles_holding_the_query(
        &PgAccounts::new(pool),
        &alice,
        &bob,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_search_takes_its_query_literally(pool: PgPool) {
    let alice = an_account(&pool, "alice").await;

    domain::identity::testing::contract::a_search_takes_its_query_literally(
        &PgAccounts::new(pool),
        &alice,
    )
    .await;
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

/// A peer on the loopback interface serving `dave_k2m9x`'s actor document under `name`.
async fn a_peer_naming_dave(name: &str) -> ActorUri {
    a_peer_describing_dave(name, None).await
}

/// … and with `icon` as its avatar.
async fn a_peer_describing_dave(name: &str, icon: Option<&str>) -> ActorUri {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let at: SocketAddr = listener.local_addr().unwrap();
    let base = format!("http://{at}");
    let mut document = serde_json::to_value(activitypub::Actor::person(
        &base,
        "dave_k2m9x",
        name,
        "-----BEGIN PUBLIC KEY-----",
    ))
    .unwrap();
    if let Some(url) = icon {
        document["icon"] = serde_json::json!({ "type": "Image", "url": url });
    }
    let document = document.to_string();
    let response = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/activity+json\r\n\
         content-length: {}\r\nconnection: close\r\n\r\n{document}",
        document.len()
    );
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let response = response.clone();
            tokio::spawn(async move {
                let mut request = [0; 4096];
                let _ = socket.read(&mut request).await;
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.shutdown().await;
            });
        }
    });
    ActorUri::parse(&format!("{base}/users/dave_k2m9x")).unwrap()
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn an_actor_is_discovered_under_its_documents_name_trimmed(pool: PgPool) {
    let dave = a_peer_naming_dave("  Dave  ").await;

    let discovered = remote_actors(pool).discover(&dave).await.unwrap();

    assert_eq!(discovered.display_name.as_deref(), Some("Dave"));
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_name_the_display_name_rules_refuse_is_not_taken_from_a_peer(pool: PgPool) {
    let dave = a_peer_naming_dave(&"x".repeat(51)).await;

    let discovered = remote_actors(pool).discover(&dave).await.unwrap();

    assert_eq!(discovered.display_name, None);
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn an_actor_is_discovered_with_the_avatar_its_document_gives(pool: PgPool) {
    let dave = a_peer_describing_dave("Dave", Some("https://cdn.dave.test/dave.png?v=2")).await;

    let discovered = remote_actors(pool).discover(&dave).await.unwrap();

    assert_eq!(
        discovered.avatar_url.as_deref(),
        Some("https://cdn.dave.test/dave.png?v=2")
    );
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn an_avatar_anywhere_but_at_an_http_url_is_not_taken_from_a_peer(pool: PgPool) {
    let dave = a_peer_describing_dave("Dave", Some("javascript:alert(1)")).await;

    let discovered = remote_actors(pool).discover(&dave).await.unwrap();

    assert_eq!(discovered.avatar_url, None);
}
