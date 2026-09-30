use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use domain::identity::testing::remote_actor;
use serde_json::json;

use crate::testing::TestApp;

#[tokio::test]
async fn a_peers_fetch_of_an_attachment_not_here_is_refused() {
    let app = TestApp::with([], []);
    let peer = remote_actor("carol_k2m9x@idp.carol.test").actor_uri;
    let uri = format!("/api/attachments/{}/content", uuid::Uuid::new_v4());
    let unsigned = Request::get(&uri).body(Body::empty()).unwrap();

    let (missing, missing_body) = app.call_as_peer(Method::GET, &uri, &peer, json!({})).await;
    let (anonymous, _) = app.send(unsigned).await;

    assert_eq!(missing, StatusCode::NOT_FOUND);
    assert_eq!(missing_body["error_description"], "Attachment not found");
    assert_eq!(anonymous, StatusCode::BAD_REQUEST);
}
