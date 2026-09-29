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
}

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
    World {
        group: group["conversationId"].as_str().unwrap().to_owned(),
        app,
        alice,
    }
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
        self.app
            .call(
                Method::POST,
                "/api/history/messages",
                Some(self.alice.id),
                Some(json!({ "entries": entries })),
            )
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
async fn the_salt_is_set_once_and_read_back() {
    let w = world().await;
    let set = |salt: String| {
        w.app.call(
            Method::POST,
            "/api/history/salt",
            Some(w.alice.id),
            Some(json!({ "salt_base64": salt })),
        )
    };
    let first = B64.encode([1; 16]);

    let unset = w
        .app
        .call(Method::GET, "/api/history/salt", Some(w.alice.id), None)
        .await;
    let stored = set(first.clone()).await;
    let kept = set(B64.encode([2; 16])).await;
    let read = w
        .app
        .call(Method::GET, "/api/history/salt", Some(w.alice.id), None)
        .await;
    let not_base64 = set("%%".to_owned()).await;
    let short = set(B64.encode([1; 15])).await;

    assert_eq!(
        unset,
        (StatusCode::NOT_FOUND, refusal("not_found", "no salt set"))
    );
    for answer in [stored, kept, read] {
        assert_eq!(answer, (StatusCode::OK, json!({ "salt_base64": first })));
    }
    assert_eq!(
        not_base64,
        (
            StatusCode::BAD_REQUEST,
            refusal("invalid_request", "salt must be base64")
        )
    );
    assert_eq!(
        short,
        (
            StatusCode::BAD_REQUEST,
            refusal("invalid_request", "salt must be exactly 16 bytes")
        )
    );
}

#[tokio::test]
async fn the_archive_needs_a_signed_in_user() {
    let w = world().await;

    for (method, uri) in [
        (Method::GET, "/api/history/messages"),
        (Method::DELETE, "/api/history/messages"),
        (Method::GET, "/api/history/salt"),
    ] {
        let (status, _) = w.app.call(method, uri, None, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{uri}");
    }
}
