use axum::http::{Method, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use domain::identity::Account;
use domain::identity::testing::account;
use serde_json::{Value, json};

use crate::testing::TestApp;

use super::*;

struct World {
    app: TestApp,
    alice: Account,
    group: String,
    /// A session of Alice's that named her laptop.
    laptops: domain::SessionId,
    laptop: Uuid,
}

/// Alice in a group, her account's history key at generation 1, set from her laptop.
async fn world() -> World {
    let (alice, bob) = (account("alice"), account("bob"));
    let app = TestApp::with([alice.clone(), bob.clone()], []);
    let (_, group) = app
        .call(
            Method::POST,
            "/api/groups",
            Some(alice.id),
            Some(json!({ "member_actor_uris": [bob.actor_uri.to_string()] })),
        )
        .await;
    let (laptops, laptop) = app.on_a_device(alice.id).await;
    let w = World {
        group: group["conversationId"].as_str().unwrap().to_owned(),
        app,
        alice,
        laptops,
        laptop,
    };
    assert_eq!(w.set_key(key_body(1, 1)).await.0, StatusCode::NO_CONTENT);
    w
}

/// A history key of generation `generation`, its bytes made of `byte`s.
fn key_body(generation: i64, byte: u8) -> Value {
    json!({
        "generation": generation,
        "salt": B64.encode([byte; 16]),
        "check_value": B64.encode([byte; 32]),
        "approval_public_key": B64.encode([byte.wrapping_add(1); 32]),
    })
}

/// The same, as `GET /api/history/key` answers it once `set_by` set it.
fn held_body(generation: i64, byte: u8, set_by: Uuid) -> Value {
    let mut body = key_body(generation, byte);
    body["set_by_device"] = json!(set_by);
    body
}

fn refusal(code: &str, description: &str) -> Value {
    json!({ "error": code, "error_description": description })
}

fn entry(conversation: &str, byte: u8) -> Value {
    json!({
        "id": Uuid::new_v4(),
        "conversation_id": conversation,
        "ciphertext": B64.encode([byte; 16]),
        "nonce": B64.encode([byte; 12]),
    })
}

impl World {
    async fn upload(&self, entries: Value) -> (StatusCode, Value) {
        self.upload_under(1, entries).await
    }

    async fn upload_under(&self, generation: i64, entries: Value) -> (StatusCode, Value) {
        self.app
            .call(
                Method::POST,
                "/api/history/messages",
                Some(self.alice.id),
                Some(json!({ "generation": generation, "entries": entries })),
            )
            .await
    }

    /// From the laptop's session.
    async fn set_key(&self, body: Value) -> (StatusCode, Value) {
        let token = self.app.token_in(self.alice.id, self.laptops);
        self.app
            .call_in(&token, Method::PUT, "/api/history/key", Some(body))
            .await
    }

    async fn key(&self) -> (StatusCode, Value) {
        self.app
            .call(Method::GET, "/api/history/key", Some(self.alice.id), None)
            .await
    }

    async fn page(&self, query: &str) -> (StatusCode, Value) {
        self.app
            .call(
                Method::GET,
                &format!("/api/history/messages{query}"),
                Some(self.alice.id),
                None,
            )
            .await
    }
}

#[tokio::test]
async fn an_upload_answers_how_many_entries_were_new() {
    let w = world().await;
    let mut tagged = entry(&w.group, 2);
    tagged["client_message_id"] = json!("client-2");
    let batch = json!([entry(&w.group, 1), tagged]);

    let first = w.upload(batch.clone()).await;
    let again = w.upload(batch).await;

    assert_eq!(first, (StatusCode::OK, json!({ "inserted": 2 })));
    assert_eq!(again, (StatusCode::OK, json!({ "inserted": 0 })));
}

#[tokio::test]
async fn an_upload_is_refused_with_the_documented_errors() {
    let w = world().await;
    let mut bad_ciphertext = entry(&w.group, 1);
    bad_ciphertext["ciphertext"] = json!("%%");
    let mut bad_nonce = entry(&w.group, 1);
    bad_nonce["nonce"] = json!("%%");
    let mut short_nonce = entry(&w.group, 1);
    short_nonce["nonce"] = json!(B64.encode([1; 11]));
    let too_many: Vec<Value> = (0..51).map(|b| entry(&w.group, b)).collect();

    for (entries, expected) in [
        (
            json!([]),
            (
                StatusCode::BAD_REQUEST,
                refusal("invalid_request", "batch size must be 1..=50"),
            ),
        ),
        (
            json!(too_many),
            (
                StatusCode::BAD_REQUEST,
                refusal("invalid_request", "batch size must be 1..=50"),
            ),
        ),
        (
            json!([bad_ciphertext]),
            (
                StatusCode::BAD_REQUEST,
                refusal("invalid_request", "ciphertext must be base64"),
            ),
        ),
        (
            json!([bad_nonce]),
            (
                StatusCode::BAD_REQUEST,
                refusal("invalid_request", "nonce must be base64"),
            ),
        ),
        (
            json!([short_nonce]),
            (
                StatusCode::BAD_REQUEST,
                refusal("invalid_request", "nonce must be 12 bytes (AES-GCM)"),
            ),
        ),
        (
            json!([entry(&Uuid::new_v4().to_string(), 1)]),
            (
                StatusCode::FORBIDDEN,
                refusal("access_denied", "not a member of one or more conversations"),
            ),
        ),
    ] {
        assert_eq!(w.upload(entries.clone()).await, expected, "{entries}");
    }
}

#[tokio::test]
async fn the_archive_pages_newest_first_with_a_cursor() {
    let w = world().await;
    let mut tagged = entry(&w.group, 1);
    tagged["client_message_id"] = json!("client-1");
    w.upload(json!([tagged, entry(&w.group, 2)])).await;
    w.upload(json!([entry(&w.group, 3)])).await;

    let (status, first) = w.page("?limit=2").await;
    let cursor = &first["next_cursor"];
    let (_, rest) = w
        .page(&format!(
            "?limit=2&after_id={}&after_created_at={}",
            cursor["after_id"].as_str().unwrap(),
            cursor["after_created_at"]
                .as_str()
                .unwrap()
                .replace('+', "%2B")
        ))
        .await;
    let last = &rest["next_cursor"];
    let (_, past_the_end) = w
        .page(&format!(
            "?after_id={}&after_created_at={}",
            last["after_id"].as_str().unwrap(),
            last["after_created_at"]
                .as_str()
                .unwrap()
                .replace('+', "%2B")
        ))
        .await;

    assert_eq!(status, StatusCode::OK, "{first}");
    let entries = first["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0]["ciphertext"], json!(B64.encode([3; 16])));
    assert_eq!(entries[0]["nonce"], json!(B64.encode([3; 12])));
    assert_eq!(entries[0]["conversation_id"], json!(w.group));
    assert_eq!(entries[0].get("client_message_id"), None);
    assert!(entries[0]["created_at"].is_string());
    assert_eq!(cursor["after_id"], entries[1]["id"]);
    assert_eq!(cursor["after_created_at"], entries[1]["created_at"]);
    assert_eq!(rest["entries"].as_array().unwrap().len(), 1);
    assert_eq!(past_the_end, json!({ "entries": [], "next_cursor": null }));
    let everything = w.page("").await.1;
    assert!(
        everything["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["client_message_id"] == "client-1")
    );
}

#[tokio::test]
async fn a_cursor_needs_both_halves_and_a_valid_date() {
    let w = world().await;
    let id = Uuid::new_v4();

    let half = w.page(&format!("?after_id={id}")).await;
    let bad_date = w
        .page(&format!("?after_id={id}&after_created_at=yesterday"))
        .await;

    assert_eq!(
        half,
        (
            StatusCode::BAD_REQUEST,
            refusal(
                "invalid_request",
                "after_id and after_created_at must be set together"
            )
        )
    );
    assert_eq!(
        bad_date,
        (
            StatusCode::BAD_REQUEST,
            refusal("invalid_request", "after_created_at not RFC3339")
        )
    );
}

#[tokio::test]
async fn clearing_answers_how_many_entries_went() {
    let w = world().await;
    w.upload(json!([entry(&w.group, 1), entry(&w.group, 2)]))
        .await;

    let cleared = w
        .app
        .call(
            Method::DELETE,
            "/api/history/messages",
            Some(w.alice.id),
            None,
        )
        .await;

    assert_eq!(cleared, (StatusCode::OK, json!({ "deleted": 2 })));
    assert_eq!(w.page("").await.1["entries"], json!([]));
}

#[tokio::test]
async fn the_key_is_read_back_as_set_with_the_device_that_set_it_and_is_none_before_the_first() {
    let alice = account("alice");
    let app = TestApp::with([alice.clone()], []);
    let (session, laptop) = app.on_a_device(alice.id).await;
    let token = app.token_in(alice.id, session);

    let unset = app
        .call_in(&token, Method::GET, "/api/history/key", None)
        .await;
    let set = app
        .call_in(
            &token,
            Method::PUT,
            "/api/history/key",
            Some(key_body(1, 1)),
        )
        .await;
    let read = app
        .call_in(&token, Method::GET, "/api/history/key", None)
        .await;

    assert_eq!(
        unset,
        (
            StatusCode::NOT_FOUND,
            refusal("not_found", "No history key set")
        )
    );
    assert_eq!(set, (StatusCode::NO_CONTENT, Value::Null));
    assert_eq!(read, (StatusCode::OK, held_body(1, 1, laptop)));
}

#[tokio::test]
async fn a_session_that_named_no_device_sets_no_key() {
    let alice = account("alice");
    let app = TestApp::with([alice.clone()], []);

    let refused = app
        .call(
            Method::PUT,
            "/api/history/key",
            Some(alice.id),
            Some(key_body(1, 1)),
        )
        .await;

    assert_eq!(
        refused,
        (
            StatusCode::FORBIDDEN,
            refusal("device_required", "Name this session's device first")
        )
    );
    assert_eq!(
        app.call(Method::GET, "/api/history/key", Some(alice.id), None)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn a_key_is_refused_with_the_documented_errors() {
    let w = world().await;
    let with = |field: &str, value: Value| {
        let mut body = key_body(2, 2);
        body[field] = value;
        body
    };

    for (body, description) in [
        (
            with("generation", json!(0)),
            "generation: must be from 1 to 2147483647",
        ),
        (with("salt", json!("%%")), "salt: must be base64"),
        (
            with("salt", json!(B64.encode([1; 15]))),
            "salt: must be 16 bytes",
        ),
        (
            with("check_value", json!(B64.encode([1; 16]))),
            "check_value: must be 32 bytes (HMAC-SHA256)",
        ),
        (
            with("approval_public_key", json!(B64.encode([1; 33]))),
            "approval_public_key: must be 32 bytes (Ed25519)",
        ),
        (
            with("approval_public_key", json!("%%")),
            "approval_public_key: must be base64",
        ),
    ] {
        assert_eq!(
            w.set_key(body.clone()).await,
            (
                StatusCode::BAD_REQUEST,
                refusal("invalid_request", description)
            ),
            "{body}"
        );
    }
    assert_eq!(w.key().await.1, held_body(1, 1, w.laptop));
}

#[tokio::test]
async fn only_the_generation_after_the_current_one_is_set_and_the_conflict_says_which_it_is() {
    let w = world().await;

    let again = w.set_key(key_body(1, 9)).await;
    let skipping = w.set_key(key_body(3, 3)).await;
    let retried = w.set_key(key_body(1, 1)).await;
    let next = w.set_key(key_body(2, 2)).await;

    let conflict = |current: i64| {
        json!({
            "error": "history_key_conflict",
            "error_description": "The history key is at another generation",
            "current_generation": current,
        })
    };
    assert_eq!(again, (StatusCode::CONFLICT, conflict(1)));
    assert_eq!(skipping, (StatusCode::CONFLICT, conflict(1)));
    assert_eq!(
        retried,
        (StatusCode::NO_CONTENT, Value::Null),
        "the very key held: a retry"
    );
    assert_eq!(next.0, StatusCode::NO_CONTENT);
    assert_eq!(w.key().await.1, held_body(2, 2, w.laptop));
}

#[tokio::test]
async fn a_conflict_before_any_key_names_generation_zero() {
    let alice = account("alice");
    let app = TestApp::with([alice.clone()], []);
    let (session, _) = app.on_a_device(alice.id).await;

    let refused = app
        .call_in(
            &app.token_in(alice.id, session),
            Method::PUT,
            "/api/history/key",
            Some(key_body(2, 2)),
        )
        .await;

    assert_eq!(refused.0, StatusCode::CONFLICT);
    assert_eq!(refused.1["current_generation"], json!(0));
}

#[tokio::test]
async fn a_later_generation_asks_for_the_password_again_and_then_erases_the_archive() {
    let w = world().await;
    w.upload(json!([entry(&w.group, 1)])).await;
    let token = w.app.token_in_signed_in_at(
        w.alice.id,
        w.laptops,
        OffsetDateTime::now_utc() - time::Duration::minutes(11),
    );
    let request = axum::http::Request::builder()
        .method(Method::PUT)
        .uri("/api/history/key")
        .header(axum::http::header::AUTHORIZATION, format!("Bearer {token}"))
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(key_body(2, 2).to_string()))
        .unwrap();

    let refused = w.app.respond(request).await;
    let kept = w.page("").await.1["entries"].as_array().unwrap().len();
    let replaced = w.set_key(key_body(2, 2)).await;

    assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        refused.headers()[axum::http::header::WWW_AUTHENTICATE],
        r#"Bearer error="insufficient_user_authentication", max_age="600""#
    );
    assert_eq!(kept, 1, "nothing erased");
    assert_eq!(replaced.0, StatusCode::NO_CONTENT);
    assert_eq!(w.page("").await.1["entries"], json!([]));
}

#[tokio::test]
async fn an_upload_under_any_generation_but_the_current_one_is_stale() {
    let w = world().await;
    w.set_key(key_body(2, 2)).await;

    let replaced = w.upload_under(1, json!([entry(&w.group, 1)])).await;
    let ahead = w.upload_under(3, json!([entry(&w.group, 1)])).await;
    let not_one = w.upload_under(0, json!([entry(&w.group, 1)])).await;
    let current = w.upload_under(2, json!([entry(&w.group, 1)])).await;

    let stale = (
        StatusCode::CONFLICT,
        refusal("stale_history_key", "Not the account's current history key"),
    );
    assert_eq!(replaced, stale);
    assert_eq!(ahead, stale);
    assert_eq!(
        not_one,
        (
            StatusCode::BAD_REQUEST,
            refusal(
                "invalid_request",
                "generation: must be from 1 to 2147483647"
            )
        )
    );
    assert_eq!(current, (StatusCode::OK, json!({ "inserted": 1 })));
}

#[tokio::test]
async fn clearing_keeps_the_key() {
    let w = world().await;
    w.upload(json!([entry(&w.group, 1)])).await;

    w.app
        .call(
            Method::DELETE,
            "/api/history/messages",
            Some(w.alice.id),
            None,
        )
        .await;

    assert_eq!(w.key().await, (StatusCode::OK, held_body(1, 1, w.laptop)));
    assert_eq!(
        w.upload(json!([entry(&w.group, 2)])).await,
        (StatusCode::OK, json!({ "inserted": 1 }))
    );
}

#[tokio::test]
async fn the_archive_needs_a_signed_in_user() {
    let w = world().await;

    for (method, uri) in [
        (Method::GET, "/api/history/messages"),
        (Method::DELETE, "/api/history/messages"),
        (Method::GET, "/api/history/key"),
        (Method::PUT, "/api/history/key"),
    ] {
        let (status, _) = w.app.call(method, uri, None, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{uri}");
    }
}
