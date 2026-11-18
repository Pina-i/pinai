use std::net::SocketAddr;

use domain::identity::{
    Accounts, ActorUri, FederatedAddress, Handle, IntroText, RemoteActors, RemoteActorsError,
    SavedIntro,
};
use federation_transport::UrlPolicy;
use infrastructure::federation::FederatedRemoteActors;
use infrastructure::postgres::{PgAccounts, PgSavedIntro};
use serde_json::{Value, json};
use sqlx::PgPool;
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use wiremock::matchers::{path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

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
async fn a_sign_up_still_to_confirm_is_found_by_its_id_only(pool: PgPool) {
    let alice = an_account(&pool, "alice").await;
    let admitted = an_account(&pool, "kai").await;
    sqlx::query("UPDATE users SET email_verified_at = NULL, admitted_at = now() WHERE id = $1")
        .bind(admitted.id.as_uuid())
        .execute(&pool)
        .await
        .unwrap();
    let signing_up = super::a_sign_up(&pool, "kaiah").await;

    domain::identity::testing::contract::a_sign_up_still_to_confirm_is_found_by_its_id_only(
        &PgAccounts::new(pool),
        &[alice, admitted],
        &signing_up,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn every_account_that_joined_counts(pool: PgPool) {
    an_account(&pool, "alice").await;
    an_account(&pool, "bob").await;
    super::a_sign_up(&pool, "kai").await;
    super::a_user(&pool).await;

    domain::identity::testing::contract::every_account_that_joined_counts(&PgAccounts::new(pool))
        .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn an_account_without_an_actor_uri_is_not_addressable(pool: PgPool) {
    let id = super::a_user(&pool).await;

    assert!(PgAccounts::new(pool).find(id).await.is_err());
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn nothing_is_saved_until_an_admin_saves(pool: PgPool) {
    domain::identity::testing::contract::nothing_is_saved_until_an_admin_saves(&PgSavedIntro::new(
        pool,
    ))
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn the_last_text_saved_is_read_back(pool: PgPool) {
    let admin = super::a_user(&pool).await;

    domain::identity::testing::contract::the_last_text_saved_is_read_back(
        &PgSavedIntro::new(pool),
        admin,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn two_saves_leave_one_row(pool: PgPool) {
    let (first, second) = (super::a_user(&pool).await, super::a_user(&pool).await);
    let intro = PgSavedIntro::new(pool.clone());
    let at = time::OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap();

    intro
        .save(
            &IntroText::parse(Some("Aotearoa"), None).unwrap(),
            first,
            at,
        )
        .await
        .unwrap();
    intro
        .save(&IntroText::parse(Some("Kāinga"), None).unwrap(), second, at)
        .await
        .unwrap();

    let rows: Vec<(Option<String>, uuid::Uuid)> =
        sqlx::query_as("SELECT name, updated_by FROM instance_intro")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(rows, vec![(Some("Kāinga".to_owned()), second.as_uuid())]);
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_row_past_a_limit_is_an_error_naming_the_table(pool: PgPool) {
    sqlx::query("INSERT INTO instance_intro (name, updated_at) VALUES ($1, now())")
        .bind("ō".repeat(41))
        .execute(&pool)
        .await
        .unwrap();

    let read = PgSavedIntro::new(pool).get().await;

    let told = format!("{:#}", anyhow::Error::from(read.unwrap_err()));
    assert!(told.contains("instance_intro"), "{told}");
    assert!(
        told.contains("instance name: 40 characters at most"),
        "{told}"
    );
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
    a_peer_serving_dave(name, icon, None, None).await
}

/// … and with `bio` and `pronouns`.
async fn a_peer_serving_dave(
    name: &str,
    icon: Option<&str>,
    bio: Option<&str>,
    pronouns: Option<&str>,
) -> ActorUri {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let at: SocketAddr = listener.local_addr().unwrap();
    let base = format!("http://{at}");
    let mut document = serde_json::to_value(
        activitypub::Actor::person(&base, "dave_k2m9x", name, "-----BEGIN PUBLIC KEY-----")
            .with_profile(bio, pronouns),
    )
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

async fn pronouns_and_bio(pool: &PgPool, actor: &ActorUri) -> (Option<String>, Option<String>) {
    sqlx::query_as("SELECT pronouns, bio FROM remote_actors WHERE actor_uri = $1")
        .bind(actor.as_str())
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn remembered_with(pool: &PgPool, actor: &ActorUri, pronouns: &str, bio: &str) {
    sqlx::query(
        "INSERT INTO remote_actors (actor_uri, instance, pronouns, bio) VALUES ($1, 'peer', $2, $3) \
         ON CONFLICT (actor_uri) DO UPDATE SET pronouns = $2, bio = $3",
    )
    .bind(actor.as_str())
    .bind(pronouns)
    .bind(bio)
    .execute(pool)
    .await
    .unwrap();
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn an_actor_is_discovered_with_the_bio_and_pronouns_its_document_gives(pool: PgPool) {
    let dave = a_peer_serving_dave("Dave", None, Some("Tom & Jerry"), Some("he")).await;

    remote_actors(pool.clone()).discover(&dave).await.unwrap();

    assert_eq!(
        pronouns_and_bio(&pool, &dave).await,
        (Some("he".to_owned()), Some("Tom & Jerry".to_owned()))
    );
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_document_without_them_clears_the_bio_and_pronouns_and_an_unreachable_one_keeps_them(
    pool: PgPool,
) {
    let unreachable = ActorUri::parse(UNREACHABLE).unwrap();
    remembered_with(&pool, &unreachable, "she", "kept").await;
    let dave = a_peer_serving_dave("Dave", None, None, Some("xe")).await;
    remembered_with(&pool, &dave, "she", "gone").await;
    let actors = remote_actors(pool.clone());

    actors.discover(&unreachable).await.unwrap();
    actors.discover(&dave).await.unwrap();

    assert_eq!(
        pronouns_and_bio(&pool, &unreachable).await,
        (Some("she".to_owned()), Some("kept".to_owned()))
    );
    assert_eq!(
        pronouns_and_bio(&pool, &dave).await,
        (None, None),
        "an unknown pronoun is none"
    );
}

/// A peer answering WebFinger with the first of what `answers` gives for the address it listens
/// at, and its actor documents with the second.
async fn a_peer_answering(answers: impl FnOnce(&str) -> (Value, Value)) -> MockServer {
    let peer = MockServer::start().await;
    let (finger, document) = answers(&peer.address().to_string());
    Mock::given(path("/.well-known/webfinger"))
        .respond_with(ResponseTemplate::new(200).set_body_json(finger))
        .mount(&peer)
        .await;
    Mock::given(path_regex("^/users/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(document))
        .mount(&peer)
        .await;
    peer
}

fn finger_to(actor: &str) -> Value {
    json!({
        "subject": "acct:someone",
        "links": [{ "rel": "self", "type": "application/activity+json", "href": actor }],
    })
}

fn person_at(at: &str, handle: &str, name: &str) -> Value {
    serde_json::to_value(activitypub::Actor::person(
        &format!("http://{at}"),
        handle,
        name,
        "-----BEGIN PUBLIC KEY-----",
    ))
    .unwrap()
}

const MAHEALANI: &str = "http://127.0.0.1:9/users/mahealani_q1x8c";

type Held = (
    Option<String>,
    Option<String>,
    Option<String>,
    OffsetDateTime,
);

async fn held_of(pool: &PgPool, actor: &str) -> Option<Held> {
    sqlx::query_as(
        "SELECT inbox_url, display_name, avatar_url, fetched_at FROM remote_actors \
         WHERE actor_uri = $1",
    )
    .bind(actor)
    .fetch_optional(pool)
    .await
    .unwrap()
}

async fn remembered(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM remote_actors")
        .fetch_one(pool)
        .await
        .unwrap()
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn an_instance_describing_another_instances_actor_leaves_what_is_held_of_them(pool: PgPool) {
    sqlx::query(
        "INSERT INTO remote_actors (actor_uri, inbox_url, instance, display_name, avatar_url) \
         VALUES ($1, $1 || '/inbox', '127.0.0.1:9', 'Mahealani', $1 || '.png')",
    )
    .bind(MAHEALANI)
    .execute(&pool)
    .await
    .unwrap();
    let held = held_of(&pool, MAHEALANI).await;
    let evil = a_peer_answering(|at| {
        let mut document = person_at(at, "x_k2m9x", "Not Mahealani");
        document["id"] = json!(MAHEALANI);
        document["inbox"] = json!(format!("http://{at}/inbox"));
        (finger_to(&format!("http://{at}/users/x_k2m9x")), document)
    })
    .await;
    let x = FederatedAddress::parse(&format!("x_k2m9x@{}", evil.address())).unwrap();

    let refused = remote_actors(pool.clone()).resolve(&x).await;

    assert!(
        matches!(refused, Err(RemoteActorsError::Unavailable(_))),
        "{refused:?}"
    );
    assert_eq!(held_of(&pool, MAHEALANI).await, held);
    assert_eq!(remembered(&pool).await, 1);
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn an_answer_no_instance_would_give_is_unavailable_and_nothing_is_remembered(pool: PgPool) {
    let too_long = format!("/users/{}", "d".repeat(ActorUri::MAX_BYTES));
    for (actor, inbox) in [
        ("/users/dave_k2m9x?page=1", "/users/dave_k2m9x/inbox"),
        (too_long.as_str(), "/users/dave_k2m9x/inbox"),
        ("/users/dave_k2m9x", "dave_k2m9x/inbox"),
        ("/users/dave_k2m9x", too_long.as_str()),
    ] {
        let peer = a_peer_answering(|at| {
            let mut document = person_at(at, "dave_k2m9x", "Dave");
            document["id"] = json!(format!("http://{at}{actor}"));
            document["inbox"] = json!(if inbox.starts_with('/') {
                format!("http://{at}{inbox}")
            } else {
                inbox.to_owned()
            });
            (finger_to(&format!("http://{at}{actor}")), document)
        })
        .await;
        let dave = FederatedAddress::parse(&format!("dave_k2m9x@{}", peer.address())).unwrap();

        let refused = remote_actors(pool.clone()).resolve(&dave).await;

        assert!(
            matches!(refused, Err(RemoteActorsError::Unavailable(_))),
            "{actor} {inbox}: {refused:?}"
        );
    }
    assert_eq!(remembered(&pool).await, 0);
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_document_naming_another_actor_is_not_taken_on_discovery(pool: PgPool) {
    let peer = a_peer_answering(|at| {
        let mut document = person_at(at, "dave_k2m9x", "Not Dave");
        document["id"] = json!(MAHEALANI);
        (json!({}), document)
    })
    .await;
    let dave = format!("http://{}/users/dave_k2m9x", peer.address());
    a_cached_actor(&pool, &dave, None).await;

    let discovered = remote_actors(pool.clone())
        .discover(&ActorUri::parse(&dave).unwrap())
        .await
        .unwrap();

    assert_eq!(discovered.display_name.as_deref(), Some("dave"));
    assert_eq!(held_of(&pool, MAHEALANI).await, None);
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn an_actor_is_discovered_at_the_inbox_its_document_gives_within_the_limits(pool: PgPool) {
    let shared = a_peer_answering(|at| {
        let mut document = person_at(at, "dave_k2m9x", "Dave");
        document["inbox"] = json!(format!("http://{at}/inbox"));
        (json!({}), document)
    })
    .await;
    let too_long = a_peer_answering(|at| {
        let mut document = person_at(at, "dave_k2m9x", "Not Dave");
        document["inbox"] = json!(format!("http://{at}/{}", "i".repeat(ActorUri::MAX_BYTES)));
        (json!({}), document)
    })
    .await;
    let dave_at = |peer: &MockServer| {
        ActorUri::parse(&format!("http://{}/users/dave_k2m9x", peer.address())).unwrap()
    };
    a_cached_actor(&pool, dave_at(&too_long).as_str(), None).await;
    let actors = remote_actors(pool);

    let discovered = actors.discover(&dave_at(&shared)).await.unwrap();
    let kept = actors.discover(&dave_at(&too_long)).await.unwrap();

    assert_eq!(
        discovered.inbox.as_str(),
        format!("http://{}/inbox", shared.address())
    );
    assert_eq!(
        kept.inbox.as_str(),
        format!("{}/inbox", dave_at(&too_long).as_str())
    );
    assert_eq!(kept.display_name.as_deref(), Some("dave"));
}
