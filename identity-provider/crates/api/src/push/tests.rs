use axum::http::Method;
use domain::identity::Account;
use domain::identity::testing::account;
use serde_json::{Value, json};

use crate::testing::TestApp;

use super::*;

struct World {
    app: TestApp,
    alice: Account,
    bob: Account,
}

fn world() -> World {
    let (alice, bob) = (account("alice"), account("bob"));
    World {
        app: TestApp::with([alice.clone(), bob.clone()], []),
        alice,
        bob,
    }
}

fn expo(token: &str) -> Value {
    json!({ "relay": "https://exp.host/--/api/v2/push/send", "token": token })
}

impl World {
    async fn push(
        &self,
        token: &str,
        method: Method,
        device: Uuid,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        self.app
            .call_in(
                token,
                method,
                &format!("/api/keys/devices/{device}/push"),
                body,
            )
            .await
    }
}

#[tokio::test]
async fn a_device_sets_its_push_registration_again_and_removes_it() {
    let w = world();
    let (session, phone) = w.app.on_a_device(w.alice.id).await;
    let token = w.app.token_in(w.alice.id, session);

    let set = w
        .push(
            &token,
            Method::PUT,
            phone,
            Some(expo("ExponentPushToken[a]")),
        )
        .await;
    let again = w
        .push(
            &token,
            Method::PUT,
            phone,
            Some(expo("ExponentPushToken[b]")),
        )
        .await;
    let removed = w.push(&token, Method::DELETE, phone, None).await;
    let none_left = w.push(&token, Method::DELETE, phone, None).await;

    for done in [set, again, removed, none_left] {
        assert_eq!(done, (StatusCode::NO_CONTENT, Value::Null));
    }
}

#[tokio::test]
async fn a_registration_that_breaks_a_rule_is_refused() {
    let w = world();
    let (session, phone) = w.app.on_a_device(w.alice.id).await;
    let token = w.app.token_in(w.alice.id, session);

    let (plain_http, body) = w
        .push(
            &token,
            Method::PUT,
            phone,
            Some(json!({ "relay": "http://exp.host/send", "token": "ExponentPushToken[a]" })),
        )
        .await;
    let (spaced, spaced_body) = w
        .push(
            &token,
            Method::PUT,
            phone,
            Some(expo("Exponent Push Token")),
        )
        .await;
    let (no_token, _) = w
        .push(
            &token,
            Method::PUT,
            phone,
            Some(json!({ "relay": "https://exp.host/--/api/v2/push/send" })),
        )
        .await;

    assert_eq!(plain_http, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert!(
        body["error_description"]
            .as_str()
            .unwrap()
            .starts_with("relay: "),
        "{body}"
    );
    assert_eq!(spaced, StatusCode::BAD_REQUEST);
    assert!(
        spaced_body["error_description"]
            .as_str()
            .unwrap()
            .starts_with("token: "),
        "{spaced_body}"
    );
    assert_eq!(no_token, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn only_the_devices_own_session_writes_its_registration() {
    let w = world();
    let (phones, phone) = w.app.on_a_device(w.alice.id).await;
    let (laptops, _) = w.app.on_a_device(w.alice.id).await;
    let (bobs, _) = w.app.on_a_device(w.bob.id).await;
    let (laptop, unnamed, bob) = (
        w.app.token_in(w.alice.id, laptops),
        w.app.token(w.alice.id),
        w.app.token_in(w.bob.id, bobs),
    );
    let registration = || Some(expo("ExponentPushToken[a]"));

    let (from_the_laptop, mismatch) = w.push(&laptop, Method::PUT, phone, registration()).await;
    let (from_no_device, required) = w.push(&unnamed, Method::PUT, phone, registration()).await;
    let (removed_by_the_laptop, _) = w.push(&laptop, Method::DELETE, phone, None).await;
    let (from_bob, _) = w.push(&bob, Method::PUT, phone, registration()).await;

    assert_eq!(
        (from_the_laptop, mismatch["error"].as_str()),
        (StatusCode::FORBIDDEN, Some("device_mismatch"))
    );
    assert_eq!(
        (from_no_device, required["error"].as_str()),
        (StatusCode::FORBIDDEN, Some("device_required"))
    );
    assert_eq!(removed_by_the_laptop, StatusCode::FORBIDDEN);
    assert_eq!(from_bob, StatusCode::FORBIDDEN);
    let token = w.app.token_in(w.alice.id, phones);
    assert_eq!(
        w.push(&token, Method::PUT, phone, registration()).await.0,
        StatusCode::NO_CONTENT
    );
}
