use axum::http::{Method, StatusCode};
use domain::UserId;
use domain::identity::testing::account;
use serde_json::json;

use crate::testing::TestApp;

#[tokio::test]
async fn a_search_answers_the_accounts_whose_handle_holds_the_query() {
    let (alice, bob) = (account("alice"), account("bob"));
    let app = TestApp::with([alice.clone(), bob], []);

    let (status, body) = app
        .call(
            Method::GET,
            "/api/users/search?q=lic",
            Some(UserId::generate()),
            None,
        )
        .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        json!([{
            "actor_uri": alice.actor_uri.as_str(),
            "username": "alice_t3st0",
            "display_name": "alice",
        }])
    );
}

#[tokio::test]
async fn a_search_needs_a_signed_in_caller() {
    let app = TestApp::with([account("alice")], []);

    let (status, body) = app
        .call(Method::GET, "/api/users/search?q=lic", None, None)
        .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "invalid_token");
}

#[tokio::test]
async fn a_search_of_less_than_two_characters_is_refused() {
    let app = TestApp::with([account("alice")], []);

    for q in ["", "a", "%20a%20"] {
        let (status, body) = app
            .call(
                Method::GET,
                &format!("/api/users/search?q={q}"),
                Some(UserId::generate()),
                None,
            )
            .await;

        assert_eq!(status, StatusCode::BAD_REQUEST, "{q:?}: {body}");
        assert_eq!(body["error"], "invalid_request");
    }
}
