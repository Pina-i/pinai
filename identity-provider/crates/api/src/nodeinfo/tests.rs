use axum::body::Body;
use axum::http::{Request, StatusCode};
use domain::identity::testing::account;
use serde_json::json;

use crate::testing::TestApp;

fn get(uri: &str) -> Request<Body> {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
}

#[tokio::test]
async fn an_instance_says_where_its_nodeinfo_is() {
    let app = TestApp::with([], []);

    let (status, links) = app.send(get("/.well-known/nodeinfo")).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        links,
        json!({ "links": [{
            "rel": "http://nodeinfo.diaspora.software/ns/schema/2.1",
            "href": "http://localhost:8080/nodeinfo/2.1",
        }] })
    );
}

#[tokio::test]
async fn an_instances_nodeinfo_names_it_and_counts_its_accounts() {
    let app = TestApp::with([account("alice"), account("bob")], []);

    let response = app.respond(get("/nodeinfo/2.1")).await;
    let kind = response.headers()["content-type"].clone();
    let (status, document) = TestApp::body_of(response).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        kind,
        "application/json; profile=\"http://nodeinfo.diaspora.software/ns/schema/2.1#\""
    );
    assert_eq!(
        document,
        json!({
            "version": "2.1",
            "software": {
                "name": "pinai",
                "version": env!("CARGO_PKG_VERSION"),
                "repository": "https://github.com/Pina-i/pinai",
            },
            "protocols": ["activitypub"],
            "services": { "inbound": [], "outbound": [] },
            "openRegistrations": true,
            "usage": { "users": { "total": 2 } },
            "metadata": { "nodeName": "Aotearoa", "nodeDescription": "Design and type people." },
        })
    );
}
