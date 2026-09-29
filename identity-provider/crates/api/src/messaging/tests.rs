use axum::http::{Method, StatusCode};
use domain::identity::testing::account;
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
