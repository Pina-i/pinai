use axum::http::{Method, StatusCode};
use domain::identity::testing::account;
use domain::profile::testing::{ProfileSeeds, own_profile};
use serde_json::json;

use crate::testing::TestApp;

#[tokio::test]
async fn the_contact_setting_is_saved_answered_and_read_on_userinfo() {
    let alice = own_profile("alice");
    let app = TestApp::with([], []);
    app.profile.profiles.sign_up(&alice).await;
    let (_, before) = app
        .call(Method::GET, "/userinfo", Some(alice.id), None)
        .await;

    let saved = app
        .call(
            Method::PATCH,
            "/api/privacy",
            Some(alice.id),
            Some(json!({ "contact_policy": "friends" })),
        )
        .await;

    assert_eq!(
        before["privacy"],
        json!({ "contact_policy": "friends_and_groups" })
    );
    assert_eq!(
        saved,
        (StatusCode::OK, json!({ "contact_policy": "friends" }))
    );
    let (_, after) = app
        .call(Method::GET, "/userinfo", Some(alice.id), None)
        .await;
    assert_eq!(after["privacy"], json!({ "contact_policy": "friends" }));
}

#[tokio::test]
async fn a_setting_outside_the_three_is_refused() {
    let alice = account("alice");
    let app = TestApp::with([alice.clone()], []);

    assert_eq!(
        app.call(
            Method::PATCH,
            "/api/privacy",
            Some(alice.id),
            Some(json!({ "contact_policy": "nobody" })),
        )
        .await,
        (
            StatusCode::BAD_REQUEST,
            json!({
                "error": "invalid_request",
                "error_description": "contact_policy must be everyone, friends_and_groups or friends",
            })
        )
    );
}

#[tokio::test]
async fn the_setting_needs_a_signed_in_user() {
    let app = TestApp::with([], []);

    let (status, _) = app
        .call(
            Method::PATCH,
            "/api/privacy",
            None,
            Some(json!({ "contact_policy": "everyone" })),
        )
        .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
