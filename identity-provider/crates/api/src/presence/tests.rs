use axum::http::{Method, StatusCode};
use domain::identity::testing::{TrustedSignatures, account, remote_actor};
use serde_json::json;

use crate::testing::TestApp;

#[tokio::test]
async fn a_poll_whose_body_is_not_the_one_signed_is_refused() {
    let alice = account("alice");
    let app = TestApp::with([alice.clone()], []);
    let peer = remote_actor("carol_k2m9x@idp.carol.test").actor_uri;
    let signed_over = json!({ "actors": [] }).to_string();
    let swapped = json!({ "actors": [alice.actor_uri.as_str()] }).to_string();

    let (status, body) = app
        .send(TestApp::signed(
            Method::POST,
            "/api/presence/batch",
            &peer,
            &swapped,
            &TrustedSignatures::digest(signed_over.as_bytes()),
        ))
        .await;

    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(
        body["error_description"],
        "Digest does not match request body"
    );
}

#[tokio::test]
async fn a_poll_signed_over_its_body_is_answered() {
    let alice = account("alice");
    let app = TestApp::with([alice.clone()], []);
    let peer = remote_actor("carol_k2m9x@idp.carol.test").actor_uri;

    let (status, body) = app
        .call_as_peer(
            Method::POST,
            "/api/presence/batch",
            &peer,
            json!({ "actors": [alice.actor_uri.as_str()] }),
        )
        .await;

    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn a_peers_stream_ends_when_the_instance_stops() {
    let alice = account("alice");
    let app = TestApp::with([alice.clone()], []);
    let peer = remote_actor("carol_k2m9x@idp.carol.test").actor_uri;
    let uri = format!(
        "/api/presence/stream?actors[]={}",
        url::form_urlencoded::byte_serialize(alice.actor_uri.as_str().as_bytes())
            .collect::<String>()
    );
    let response = app
        .respond(TestApp::signed(
            Method::GET,
            &uri,
            &peer,
            "",
            &TrustedSignatures::digest(b""),
        ))
        .await;
    assert_eq!(response.status(), StatusCode::OK);

    app.shutdown.cancel();
    let body = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        http_body_util::BodyExt::collect(response.into_body()),
    )
    .await;

    assert!(body.is_ok(), "the stream outlived the instance");
}
