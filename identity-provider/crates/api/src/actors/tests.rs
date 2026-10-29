use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use domain::identity::testing::account;
use domain::social::SocialGraph;
use serde_json::json;

use crate::testing::{PUBLIC_KEY_PEM, TestApp};

async fn get(app: &TestApp, uri: &str) -> (StatusCode, String, serde_json::Value) {
    let response = app
        .respond(Request::get(uri).body(Body::empty()).unwrap())
        .await;
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .map(|v| v.to_str().unwrap().to_owned())
        .unwrap_or_default();
    let (status, body) = TestApp::body_of(response).await;
    (status, content_type, body)
}

#[tokio::test]
async fn web_finger_points_an_address_of_ours_at_its_actor() {
    let alice = account("alice");
    let app = TestApp::with([alice.clone()], []);

    let (status, content_type, body) = get(
        &app,
        "/.well-known/webfinger?resource=acct:alice_t3st0@localhost:8080",
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(content_type, "application/jrd+json; charset=utf-8");
    assert_eq!(body["subject"], "acct:alice_t3st0@localhost:8080");
    assert_eq!(body["links"][0]["rel"], "self");
    assert_eq!(body["links"][0]["type"], "application/activity+json");
    assert_eq!(body["links"][0]["href"], alice.actor_uri.as_str());
}

#[tokio::test]
async fn web_finger_knows_nobody_elsewhere_nor_unknown() {
    let app = TestApp::with([account("alice")], []);

    for resource in [
        "acct:alice_t3st0@idp.other.test",
        "acct:bob_t3st0@localhost:8080",
    ] {
        let (status, _, body) =
            get(&app, &format!("/.well-known/webfinger?resource={resource}")).await;

        assert_eq!(status, StatusCode::NOT_FOUND, "{resource}");
        assert_eq!(body["error_description"], "User not found");
    }
}

#[tokio::test]
async fn an_accounts_person_publishes_its_name_inbox_and_the_instance_key() {
    let alice = account("alice");
    let app = TestApp::with([alice.clone()], []);

    let (status, content_type, body) = get(&app, "/users/alice_t3st0").await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(content_type, "application/activity+json; charset=utf-8");
    assert_eq!(body["type"], "Person");
    assert_eq!(body["id"], alice.actor_uri.as_str());
    assert_eq!(body["preferredUsername"], "alice_t3st0");
    assert_eq!(body["name"], "alice");
    assert_eq!(body["inbox"], format!("{}/inbox", alice.actor_uri));
    assert_eq!(
        body["publicKey"]["id"],
        format!("{}#main-key", alice.actor_uri)
    );
    assert_eq!(body["publicKey"]["publicKeyPem"], PUBLIC_KEY_PEM);
}

#[tokio::test]
async fn an_accounts_person_carries_its_avatar_and_none_without_one() {
    let alice = account("alice");
    let avatar = format!("http://localhost:8080/avatars/{}.png?v=1", alice.id);
    let alice = domain::identity::Account {
        avatar_url: Some(avatar.clone()),
        ..alice
    };
    let app = TestApp::with([alice, account("bob")], []);

    let (_, _, with) = get(&app, "/users/alice_t3st0").await;
    let (_, _, without) = get(&app, "/users/bob_t3st0").await;

    assert_eq!(with["icon"], json!({ "type": "Image", "url": avatar }));
    assert!(without.get("icon").is_none(), "{without}");
}

#[tokio::test]
async fn an_accounts_person_carries_its_bio_and_pronouns_and_none_it_lacks() {
    use domain::profile::testing::{ProfileSeeds, own_profile};
    let (alice, bob) = (account("alice"), account("bob"));
    let app = TestApp::with([alice.clone(), bob.clone()], []);
    app.profile
        .profiles
        .sign_up(&domain::profile::OwnProfile {
            id: alice.id,
            pronouns: Some(domain::profile::Pronouns::She),
            bio: Some("Tom & Jerry\nkia ora".to_owned()),
            ..own_profile("alice")
        })
        .await;
    app.profile
        .profiles
        .sign_up(&domain::profile::OwnProfile {
            id: bob.id,
            ..own_profile("bob")
        })
        .await;

    let (_, _, with) = get(&app, "/users/alice_t3st0").await;
    let (_, _, without) = get(&app, "/users/bob_t3st0").await;

    assert_eq!(with["summary"], "Tom &amp; Jerry<br>kia ora");
    assert_eq!(with["pronouns"], "she");
    assert!(without.get("summary").is_none(), "{without}");
    assert!(without.get("pronouns").is_none(), "{without}");
}

#[tokio::test]
async fn an_account_without_a_display_name_is_named_by_its_handle() {
    let alice = domain::identity::Account {
        display_name: None,
        ..account("alice")
    };
    let app = TestApp::with([alice], []);

    let (_, _, body) = get(&app, "/users/alice_t3st0").await;

    assert_eq!(body["name"], "alice_t3st0");
}

#[tokio::test]
async fn no_account_no_actor() {
    let app = TestApp::with([account("alice")], []);

    for uri in [
        "/users/bob_t3st0",
        "/users/bob_t3st0/outbox",
        "/users/bob_t3st0/followers",
        "/users/bob_t3st0/following",
    ] {
        let (status, _, body) = get(&app, uri).await;

        assert_eq!(status, StatusCode::NOT_FOUND, "{uri}");
        assert_eq!(body["error_description"], "User not found");
    }
}

#[tokio::test]
async fn the_instance_actor_publishes_the_instance_key() {
    let app = TestApp::with([], []);

    let (status, content_type, body) = get(&app, "/actor").await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(content_type, "application/activity+json; charset=utf-8");
    assert_eq!(body["type"], "Application");
    assert_eq!(body["id"], "http://localhost:8080/actor");
    assert_eq!(
        body["publicKey"]["id"],
        "http://localhost:8080/actor#main-key"
    );
    assert_eq!(body["publicKey"]["publicKeyPem"], PUBLIC_KEY_PEM);
}

#[tokio::test]
async fn the_outbox_is_empty() {
    let alice = account("alice");
    let app = TestApp::with([alice.clone()], []);

    let (status, _, body) = get(&app, "/users/alice_t3st0/outbox").await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["type"], "OrderedCollection");
    assert_eq!(body["id"], format!("{}/outbox", alice.actor_uri));
    assert_eq!(body["totalItems"], 0);
    assert_eq!(body["orderedItems"], json!([]));
}

#[tokio::test]
async fn the_collections_never_show_who_the_account_is_friends_with() {
    let (alice, bob) = (account("alice"), account("bob"));
    let app = TestApp::with([alice.clone(), bob.clone()], []);
    let request = app
        .peers
        .graph
        .record_local_request(&bob, &alice)
        .await
        .unwrap()
        .target_side;
    app.peers.graph.accept(&request, &alice).await.unwrap();

    for collection in ["followers", "following"] {
        let (status, _, body) = get(&app, &format!("/users/alice_t3st0/{collection}")).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["id"], format!("{}/{collection}", alice.actor_uri));
        assert_eq!(body["totalItems"], 0, "{collection}");
        assert_eq!(body["orderedItems"], json!([]), "{collection}");
    }
}

#[tokio::test]
async fn the_instance_is_healthy() {
    let app = TestApp::with([], []);

    let (status, body) = app.call(Method::GET, "/health", None, None).await;

    assert_eq!((status, body), (StatusCode::OK, json!({ "ok": true })));
}
