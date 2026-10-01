use axum::http::{Method, StatusCode};
use domain::identity::testing::account;
use domain::social::testing::{BLOCKED, KEPT_OUT_BY_THE_SETTING};
use serde_json::{Value, json};

use crate::testing::TestApp;

#[tokio::test]
async fn an_older_page_is_read_with_the_cursor_a_page_returned() {
    let (alice, bob) = (account("alice"), account("bob"));
    let app = TestApp::with([alice.clone(), bob.clone()], []);
    for n in 1..=3 {
        let (status, _) = app
            .call(
                Method::POST,
                "/api/dm",
                Some(alice.id),
                Some(json!({ "recipient_address": bob.username, "mls_ciphertext": format!("AQID{n}A==") })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED);
    }
    let (_, sent) = app.call(Method::GET, "/api/dm", Some(alice.id), None).await;
    let conversation = sent[0]["conversation_id"].as_str().unwrap().to_owned();
    let (_, first) = app
        .call(
            Method::GET,
            &format!("/api/dm/{conversation}?limit=2"),
            Some(alice.id),
            None,
        )
        .await;
    let oldest: &Value = &first[1];

    let (status, older) = app
        .call(
            Method::GET,
            &format!(
                "/api/dm/{conversation}?limit=2&cursor_created_at={}&cursor_id={}",
                oldest["created_at"].as_str().unwrap(),
                oldest["id"].as_str().unwrap()
            ),
            Some(alice.id),
            None,
        )
        .await;

    assert_eq!(status, StatusCode::OK, "{older}");
    assert_eq!(older.as_array().map(Vec::len), Some(1));
}

fn refusal(description: &str) -> Value {
    json!({ "error": "access_denied", "error_description": description })
}

async fn dm(app: &TestApp, from: &domain::identity::Account, to: &str) -> (StatusCode, Value) {
    app.call(
        Method::POST,
        "/api/dm",
        Some(from.id),
        Some(json!({ "recipient_address": to, "mls_ciphertext": "AQID" })),
    )
    .await
}

#[tokio::test]
async fn a_dm_to_someone_the_sender_blocked_is_refused() {
    let (alice, bob) = (account("alice"), account("bob"));
    let app = TestApp::with([alice.clone(), bob.clone()], []);
    app.reach.set(alice.id, &bob.actor_uri, BLOCKED);

    assert_eq!(
        dm(&app, &alice, &bob.username).await,
        (StatusCode::FORBIDDEN, refusal("You blocked this user"))
    );
}

/// Byte for byte the same answer: nothing in it may tell a block from the setting.
#[tokio::test]
async fn a_dm_to_someone_who_cannot_be_reached_is_refused_alike_whatever_the_cause() {
    let (alice, bob) = (account("alice"), account("bob"));
    let mut answers = Vec::new();
    for kept_out in [BLOCKED, KEPT_OUT_BY_THE_SETTING] {
        let app = TestApp::with([alice.clone(), bob.clone()], []);
        app.reach.set(bob.id, &alice.actor_uri, kept_out);

        answers.push(dm(&app, &alice, &bob.username).await);
        let (_, listed) = app.call(Method::GET, "/api/dm", Some(alice.id), None).await;
        assert_eq!(listed, json!([]), "no DM opened");
    }
    assert_eq!(
        answers,
        vec![
            (
                StatusCode::FORBIDDEN,
                refusal("Message could not be delivered")
            );
            2
        ]
    );
}

#[tokio::test]
async fn an_edit_in_a_dm_follows_the_same_rules() {
    let (alice, bob) = (account("alice"), account("bob"));
    let app = TestApp::with([alice.clone(), bob.clone()], []);
    let (_, sent) = dm(&app, &alice, &bob.username).await;
    let edit = format!("/api/dm/{}/edit", sent["id"].as_str().unwrap());
    let body = Some(json!({ "mls_ciphertext": "BAUG" }));

    app.reach
        .set(bob.id, &alice.actor_uri, KEPT_OUT_BY_THE_SETTING);
    assert_eq!(
        app.call(Method::PATCH, &edit, Some(alice.id), body.clone())
            .await,
        (
            StatusCode::FORBIDDEN,
            refusal("Message could not be delivered")
        )
    );
    app.reach.set(alice.id, &bob.actor_uri, BLOCKED);
    assert_eq!(
        app.call(Method::PATCH, &edit, Some(alice.id), body).await,
        (StatusCode::FORBIDDEN, refusal("You blocked this user"))
    );
}

#[tokio::test]
async fn a_dm_to_an_instance_that_does_not_answer_is_a_bad_gateway() {
    let alice = account("alice");
    let app = TestApp::knowing(
        [alice.clone()],
        domain::identity::testing::InMemoryRemoteActors::default().and_down("idp.down.test"),
    );

    let (status, body) = dm(&app, &alice, "dave_k2m9x@idp.down.test").await;

    assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
}
