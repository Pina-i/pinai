use axum::http::{Method, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use domain::identity::Account;
use domain::identity::testing::account;
use serde_json::{Value, json};
use time::format_description::well_known::Rfc3339;

use crate::testing::TestApp;

use super::*;

/// Alice's laptop, which set generation 1 and is approved by its words, and a fresh device of
/// hers nobody approved, each on a session of its own.
struct World {
    app: TestApp,
    alice: Account,
    laptop_session: domain::SessionId,
    laptops: String,
    laptop: Uuid,
    freshs: String,
    fresh: Uuid,
}

fn key_body(generation: i64) -> Value {
    json!({
        "generation": generation,
        "salt": B64.encode([1; 16]),
        "check_value": B64.encode([1; 32]),
        "approval_public_key": B64.encode([2; 32]),
    })
}

fn refusal(code: &str, description: &str) -> Value {
    json!({ "error": code, "error_description": description })
}

async fn world() -> World {
    let alice = account("alice");
    let app = TestApp::with([alice.clone()], []);
    let (laptop_session, laptop) = app.on_a_device(alice.id).await;
    let (fresh_session, fresh) = app.on_a_device(alice.id).await;
    let (laptops, freshs) = (
        app.token_in(alice.id, laptop_session),
        app.token_in(alice.id, fresh_session),
    );
    let (set, body) = app
        .call_in(&laptops, Method::PUT, "/api/history/key", Some(key_body(1)))
        .await;
    assert_eq!(set, StatusCode::NO_CONTENT, "{body}");
    app.approved_by_words(&alice, &laptops, laptop, 1, [2; 32])
        .await;
    World {
        app,
        alice,
        laptop_session,
        laptops,
        laptop,
        freshs,
        fresh,
    }
}

impl World {
    async fn ask(&self, token: &str) -> (StatusCode, Value) {
        self.app
            .call_in(token, Method::POST, "/api/history/start-over", None)
            .await
    }

    async fn read(&self, token: &str) -> (StatusCode, Value) {
        self.app
            .call_in(token, Method::GET, "/api/history/start-over", None)
            .await
    }

    async fn end(&self, token: &str, id: &Value) -> (StatusCode, Value) {
        self.app
            .call_in(
                token,
                Method::DELETE,
                &format!("/api/history/start-over/{}", id.as_str().unwrap()),
                None,
            )
            .await
    }
}

fn at(value: &Value) -> OffsetDateTime {
    OffsetDateTime::parse(value.as_str().unwrap(), &Rfc3339).unwrap()
}

#[tokio::test]
async fn a_device_not_approved_asks_and_asking_again_answers_the_same_request() {
    let w = world().await;

    let (opened, first) = w.ask(&w.freshs).await;
    let (again, second) = w.ask(&w.freshs).await;

    assert_eq!(opened, StatusCode::CREATED, "{first}");
    assert_eq!(
        at(&first["ready_at"]),
        at(&first["created_at"]) + domain::e2ee::START_OVER_WAIT,
        "the laptop was used as the request opened"
    );
    assert_eq!((again, second), (StatusCode::OK, first));
}

#[tokio::test]
async fn asking_is_refused_with_the_documented_errors() {
    let w = world().await;
    let unnamed = w.app.token(w.alice.id);
    let (other, _) = w.app.on_a_device(w.alice.id).await;
    let others = w.app.token_in(w.alice.id, other);

    let approved = w.ask(&w.laptops).await;
    let no_device = w.ask(&unnamed).await;
    w.ask(&w.freshs).await;
    let pending = w.ask(&others).await;

    assert_eq!(
        approved,
        (
            StatusCode::CONFLICT,
            refusal(
                "already_approved",
                "An approved device replaces the history key itself"
            )
        )
    );
    assert_eq!(
        no_device,
        (
            StatusCode::FORBIDDEN,
            refusal("device_required", "Name this session's device first")
        )
    );
    assert_eq!(
        pending,
        (
            StatusCode::CONFLICT,
            refusal(
                "start_over_pending",
                "Another device of the account is starting over"
            )
        )
    );
}

#[tokio::test]
async fn an_account_without_a_history_key_has_nothing_to_start_over_from() {
    let alice = account("alice");
    let app = TestApp::with([alice.clone()], []);
    let (session, _) = app.on_a_device(alice.id).await;

    let refused = app
        .call_in(
            &app.token_in(alice.id, session),
            Method::POST,
            "/api/history/start-over",
            None,
        )
        .await;

    assert_eq!(
        refused,
        (
            StatusCode::CONFLICT,
            refusal(
                "no_history_key",
                "The account has no history key to start over from"
            )
        )
    );
}

#[tokio::test]
async fn the_asker_and_the_approved_devices_read_the_request_and_no_one_else() {
    let w = world().await;
    let (other, _) = w.app.on_a_device(w.alice.id).await;
    let others = w.app.token_in(w.alice.id, other);
    let none = w.read(&w.laptops).await;
    let (_, asked) = w.ask(&w.freshs).await;

    let by_the_asker = w.read(&w.freshs).await;
    let by_the_laptop = w.read(&w.laptops).await;
    let by_another = w.read(&others).await;

    assert_eq!(none.0, StatusCode::NOT_FOUND);
    let pending = json!({
        "id": asked["id"],
        "device_id": w.fresh,
        "display_name": "Web client",
        "created_at": asked["created_at"],
        "ready_at": asked["ready_at"],
        "ended": null,
    });
    assert_eq!(by_the_asker, (StatusCode::OK, pending.clone()));
    assert_eq!(by_the_laptop, (StatusCode::OK, pending));
    assert_eq!(
        by_another,
        (
            StatusCode::FORBIDDEN,
            refusal(
                "approval_required",
                "This takes a device approved under the current history key"
            )
        )
    );
}

#[tokio::test]
async fn an_approved_device_cancels_without_a_recent_password_and_once_only() {
    let w = world().await;
    let (_, asked) = w.ask(&w.freshs).await;
    let long_ago = w.app.token_in_signed_in_at(
        w.alice.id,
        w.laptop_session,
        OffsetDateTime::now_utc() - time::Duration::days(3),
    );

    let cancelled = w.end(&long_ago, &asked["id"]).await;
    let again = w.end(&w.laptops, &asked["id"]).await;
    let unknown = w.end(&w.laptops, &json!(Uuid::new_v4().to_string())).await;
    let by_the_asker = w.read(&w.freshs).await;
    let by_the_laptop = w.read(&w.laptops).await;

    assert_eq!(cancelled, (StatusCode::NO_CONTENT, Value::Null));
    assert_eq!(
        again,
        (
            StatusCode::GONE,
            refusal("start_over_ended", "The start over request has ended")
        )
    );
    assert_eq!(unknown.0, StatusCode::NOT_FOUND);
    assert_eq!(
        by_the_asker.0,
        StatusCode::OK,
        "it reads how its request ended"
    );
    assert_eq!(by_the_asker.1["id"], asked["id"]);
    assert_eq!(by_the_asker.1["ended"]["reason"], "cancelled");
    assert!(by_the_asker.1["ended"]["at"].is_string());
    assert_eq!(by_the_laptop.0, StatusCode::NOT_FOUND, "none open");
}

#[tokio::test]
async fn a_device_not_approved_sets_the_next_generation_through_its_matured_request_only() {
    let w = world().await;

    let without = w
        .app
        .call_in(
            &w.freshs,
            Method::PUT,
            "/api/history/key",
            Some(key_body(2)),
        )
        .await;
    let (_, asked) = w.ask(&w.freshs).await;
    let too_soon = w
        .app
        .call_in(
            &w.freshs,
            Method::PUT,
            "/api/history/key",
            Some(key_body(2)),
        )
        .await;

    assert_eq!(
        without,
        (
            StatusCode::FORBIDDEN,
            refusal(
                "start_over_required",
                "A device not approved starts over through a request"
            )
        )
    );
    assert_eq!(
        too_soon,
        (
            StatusCode::FORBIDDEN,
            json!({
                "error": "start_over_not_ready",
                "error_description": "No approved device may be used for a week first",
                "ready_at": asked["ready_at"],
            })
        )
    );
}

#[tokio::test]
async fn a_device_not_approved_revokes_no_approved_device_but_itself() {
    let w = world().await;

    let refused = w
        .app
        .call_in(
            &w.freshs,
            Method::POST,
            &format!("/api/keys/devices/{}/revoke", w.laptop),
            None,
        )
        .await;
    let itself = w
        .app
        .call_in(
            &w.freshs,
            Method::POST,
            &format!("/api/keys/devices/{}/revoke", w.fresh),
            None,
        )
        .await;

    assert_eq!(
        refused,
        (
            StatusCode::FORBIDDEN,
            refusal(
                "approval_required",
                "This takes a device approved under the current history key"
            )
        )
    );
    assert_eq!(itself, (StatusCode::NO_CONTENT, Value::Null));
}
