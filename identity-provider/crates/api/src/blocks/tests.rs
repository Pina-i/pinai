use axum::http::{Method, StatusCode};
use domain::identity::testing::{account, remote_actor};
use domain::identity::{Account, ActorUri};
use domain::social::{MAX_BLOCKS, SocialGraph};
use serde_json::{Value, json};

use crate::testing::TestApp;

struct World {
    app: TestApp,
    alice: Account,
    bob: Account,
}

fn world() -> World {
    let (alice, bob) = (account("alice"), account("bob"));
    let app = TestApp::with(
        [alice.clone(), bob.clone()],
        [remote_actor("dave_k2m9x@idp.dave.test")],
    );
    World { app, alice, bob }
}

fn refusal(code: &str, description: &str) -> Value {
    json!({ "error": code, "error_description": description })
}

fn encoded(actor: &ActorUri) -> String {
    url::form_urlencoded::byte_serialize(actor.as_str().as_bytes()).collect()
}

impl World {
    async fn block(&self, by: &Account, actor_uri: &str) -> (StatusCode, Value) {
        self.app
            .call(
                Method::POST,
                "/api/blocks",
                Some(by.id),
                Some(json!({ "actor_uri": actor_uri })),
            )
            .await
    }

    async fn befriend(&self, requester: &Account, target: &Account) {
        let request = self
            .app
            .peers
            .graph
            .record_local_request(requester, target)
            .await
            .unwrap()
            .target_side;
        self.app.peers.graph.accept(&request, target).await.unwrap();
    }
}

#[tokio::test]
async fn a_block_answers_204_and_is_listed_with_the_actors_name() {
    let w = world();
    w.befriend(&w.bob, &w.alice).await;

    let (status, _) = w.block(&w.alice, w.bob.actor_uri.as_str()).await;

    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, listed) = w
        .app
        .call(Method::GET, "/api/blocks", Some(w.alice.id), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let listed = listed.as_array().unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0]["actor_uri"], w.bob.actor_uri.as_str());
    assert_eq!(listed[0]["display_name"], json!(w.bob.display_name));
    assert_eq!(listed[0]["avatar_url"], Value::Null);
    let blocked_at = listed[0]["blocked_at"].as_str().unwrap();
    assert!(
        time::OffsetDateTime::parse(blocked_at, &time::format_description::well_known::Rfc3339)
            .is_ok(),
        "{blocked_at}"
    );
}

#[tokio::test]
async fn a_block_ends_the_friendship() {
    let w = world();
    w.befriend(&w.bob, &w.alice).await;

    w.block(&w.alice, w.bob.actor_uri.as_str()).await;

    for (owner, other) in [(&w.alice, &w.bob), (&w.bob, &w.alice)] {
        let (_, friends) = w
            .app
            .call(Method::GET, "/api/friends", Some(owner.id), None)
            .await;
        assert_eq!(
            friends,
            json!([]),
            "{} still has {}",
            owner.username,
            other.username
        );
    }
}

#[tokio::test]
async fn blocking_again_answers_204_and_lists_once() {
    let w = world();

    w.block(&w.alice, "https://idp.dave.test/users/dave_k2m9x")
        .await;
    let (status, _) = w
        .block(&w.alice, "https://idp.dave.test/users/dave_k2m9x")
        .await;

    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, listed) = w
        .app
        .call(Method::GET, "/api/blocks", Some(w.alice.id), None)
        .await;
    assert_eq!(listed.as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn a_block_is_refused_with_the_documented_errors() {
    let w = world();

    assert_eq!(
        w.block(&w.alice, w.alice.actor_uri.as_str()).await,
        (
            StatusCode::BAD_REQUEST,
            refusal("invalid_request", "You can't block yourself")
        )
    );
    for not_an_actor in [
        "bob",
        "bob@localhost:8080",
        "ftp://idp.dave.test/users/dave",
    ] {
        assert_eq!(
            w.block(&w.alice, not_an_actor).await,
            (
                StatusCode::BAD_REQUEST,
                refusal("invalid_request", "Invalid actor URI")
            ),
            "{not_an_actor}"
        );
    }
    let (_, listed) = w
        .app
        .call(Method::GET, "/api/blocks", Some(w.alice.id), None)
        .await;
    assert_eq!(listed, json!([]));
}

#[tokio::test]
async fn a_full_block_list_takes_no_one_new() {
    let w = world();
    for i in 0..MAX_BLOCKS {
        let stranger = ActorUri::parse(&format!("https://idp.eve.test/users/eve_{i:05}")).unwrap();
        w.app.peers.graph.block(&w.alice, &stranger).await.unwrap();
    }

    assert_eq!(
        w.block(&w.alice, w.bob.actor_uri.as_str()).await,
        (
            StatusCode::BAD_REQUEST,
            refusal("invalid_request", "You can't block more than 1000 people")
        )
    );
    let (status, _) = w
        .block(&w.alice, "https://idp.eve.test/users/eve_00007")
        .await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "blocking again changes nothing"
    );
}

#[tokio::test]
async fn an_unblock_answers_204_once_then_404() {
    let w = world();
    w.block(&w.alice, w.bob.actor_uri.as_str()).await;
    let uri = format!("/api/blocks/{}", encoded(&w.bob.actor_uri));

    let (status, _) = w
        .app
        .call(Method::DELETE, &uri, Some(w.alice.id), None)
        .await;

    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, listed) = w
        .app
        .call(Method::GET, "/api/blocks", Some(w.alice.id), None)
        .await;
    assert_eq!(listed, json!([]));
    assert_eq!(
        w.app
            .call(Method::DELETE, &uri, Some(w.alice.id), None)
            .await,
        (StatusCode::NOT_FOUND, refusal("not_found", "Not blocked"))
    );
    assert_eq!(
        w.app
            .call(
                Method::DELETE,
                "/api/blocks/not-a-uri",
                Some(w.alice.id),
                None
            )
            .await,
        (StatusCode::NOT_FOUND, refusal("not_found", "Not blocked"))
    );
}

#[tokio::test]
async fn a_block_list_is_its_owners() {
    let w = world();
    w.block(&w.alice, "https://idp.dave.test/users/dave_k2m9x")
        .await;

    let (_, listed) = w
        .app
        .call(Method::GET, "/api/blocks", Some(w.bob.id), None)
        .await;
    assert_eq!(listed, json!([]));
    let uri = format!(
        "/api/blocks/{}",
        encoded(&ActorUri::parse("https://idp.dave.test/users/dave_k2m9x").unwrap())
    );
    let (status, _) = w.app.call(Method::DELETE, &uri, Some(w.bob.id), None).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "bob lifts no block of alice's"
    );
    let (_, listed) = w
        .app
        .call(Method::GET, "/api/blocks", Some(w.alice.id), None)
        .await;
    assert_eq!(listed.as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn the_block_routes_need_a_signed_in_user() {
    let w = world();

    for (method, uri, body) in [
        (Method::GET, "/api/blocks".to_owned(), None),
        (
            Method::POST,
            "/api/blocks".to_owned(),
            Some(json!({ "actor_uri": w.bob.actor_uri.as_str() })),
        ),
        (
            Method::DELETE,
            format!("/api/blocks/{}", encoded(&w.bob.actor_uri)),
            None,
        ),
    ] {
        let (status, _) = w.app.call(method.clone(), &uri, None, body).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {uri}");
    }
}
