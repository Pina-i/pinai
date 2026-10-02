use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use domain::identity::Account;
use domain::identity::testing::{InMemoryRemoteActors, account, remote_actor};
use domain::social::testing::BLOCKED;
use serde_json::{Value, json};

use crate::testing::TestApp;

use super::*;

struct World {
    app: TestApp,
    alice: Account,
    bob: Account,
    carol: Account,
}

fn world() -> World {
    let (alice, bob, carol) = (account("alice"), account("bob"), account("carol"));
    let app = TestApp::with(
        [alice.clone(), bob.clone(), carol.clone()],
        [remote_actor("dave_k2m9x@idp.dave.test")],
    );
    World {
        app,
        alice,
        bob,
        carol,
    }
}

fn refusal(code: &str, description: &str) -> Value {
    json!({ "error": code, "error_description": description })
}

impl World {
    async fn request(&self, from: &Account, address: &str) -> (StatusCode, Value) {
        self.app
            .call(
                Method::POST,
                "/api/friends/request",
                Some(from.id),
                Some(json!({ "address": address })),
            )
            .await
    }

    /// The id of the request `to` received from `from`.
    async fn incoming_id(&self, from: &Account, to: &Account) -> String {
        self.request(from, &to.username).await;
        let (_, incoming) = self
            .app
            .call(Method::GET, "/api/friends/incoming", Some(to.id), None)
            .await;
        incoming[0]["friendship_id"].as_str().unwrap().to_owned()
    }
}

#[tokio::test]
async fn a_friend_request_answers_201_with_the_pending_side() {
    let w = world();

    let (status, body) = w.request(&w.alice, &w.bob.username).await;

    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["status"], "pending");
    assert!(
        body["friendship_id"]
            .as_str()
            .unwrap()
            .parse::<uuid::Uuid>()
            .is_ok()
    );
}

#[tokio::test]
async fn a_friend_request_is_refused_with_the_documented_errors() {
    let w = world();
    let friends = w.incoming_id(&w.alice, &w.bob).await;
    w.app
        .call(
            Method::POST,
            &format!("/api/friends/{friends}/accept"),
            Some(w.bob.id),
            None,
        )
        .await;

    for (address, status, expected) in [
        (
            "nobody_t3st0",
            StatusCode::NOT_FOUND,
            refusal("not_found", "User not found"),
        ),
        (
            "not an address",
            StatusCode::NOT_FOUND,
            refusal("not_found", "User not found"),
        ),
        (
            w.alice.username.as_str(),
            StatusCode::BAD_REQUEST,
            refusal("invalid_request", "Cannot friend yourself"),
        ),
        (
            w.bob.username.as_str(),
            StatusCode::BAD_REQUEST,
            refusal("invalid_request", "Already friends"),
        ),
    ] {
        assert_eq!(
            w.request(&w.alice, address).await,
            (status, expected),
            "{address}"
        );
    }
}

#[tokio::test]
async fn a_request_to_a_remote_address_answers_201() {
    let w = world();

    let (status, body) = w.request(&w.alice, "dave_k2m9x@idp.dave.test").await;

    assert_eq!(
        (status, &body["status"]),
        (StatusCode::CREATED, &json!("pending"))
    );
}

#[tokio::test]
async fn a_request_without_a_valid_token_is_refused_with_401() {
    let w = world();
    let bad_token = Request::get("/api/friends")
        .header(header::AUTHORIZATION, "Bearer forged")
        .body(Body::empty())
        .unwrap();

    assert_eq!(
        w.app.call(Method::GET, "/api/friends", None, None).await,
        (
            StatusCode::UNAUTHORIZED,
            refusal("invalid_token", "Missing or invalid Authorization header")
        )
    );
    assert_eq!(
        w.app.send(bad_token).await,
        (
            StatusCode::UNAUTHORIZED,
            refusal("invalid_token", "Invalid or expired access token")
        )
    );
}

#[tokio::test]
async fn incoming_requests_list_the_pending_requests_received() {
    let w = world();
    w.request(&w.alice, &w.bob.username).await;

    let (status, body) = w
        .app
        .call(Method::GET, "/api/friends/incoming", Some(w.bob.id), None)
        .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        json!([{
            "friendship_id": body[0]["friendship_id"],
            "actor_uri": w.alice.actor_uri.as_str(),
            "username": w.alice.username,
            "display_name": "alice",
            "status": "pending",
        }])
    );
    assert!(body[0]["friendship_id"].is_string());
}

#[tokio::test]
async fn an_accepted_request_answers_204_and_lists_both_as_friends() {
    let w = world();
    let request = w.incoming_id(&w.alice, &w.bob).await;

    let (status, _) = w
        .app
        .call(
            Method::POST,
            &format!("/api/friends/{request}/accept"),
            Some(w.bob.id),
            None,
        )
        .await;

    assert_eq!(status, StatusCode::NO_CONTENT);
    let (listed, friends) = w
        .app
        .call(Method::GET, "/api/friends", Some(w.alice.id), None)
        .await;
    let since = friends[0]["since"].as_str().unwrap_or_default().to_owned();
    assert!(
        time::OffsetDateTime::parse(&since, &time::format_description::well_known::Rfc3339).is_ok(),
        "since {since:?} is an RFC 3339 date"
    );
    assert_eq!(
        (listed, friends),
        (
            StatusCode::OK,
            json!([{
                "username": w.bob.username,
                "display_name": "bob",
                "avatar_url": null,
                "friend_actor_uri": w.bob.actor_uri.as_str(),
                "instance": "local",
                "since": since,
            }])
        )
    );
}

#[tokio::test]
async fn answering_a_request_one_may_not_answer_is_refused_naming_the_verb() {
    let w = world();
    let request = w.incoming_id(&w.alice, &w.bob).await;
    let (_, sent) = w.request(&w.alice, &w.carol.username).await;
    let own_request = sent["friendship_id"].as_str().unwrap().to_owned();
    let unknown = uuid::Uuid::new_v4();

    for (method, verb) in [(Method::POST, "accept"), (Method::DELETE, "reject")] {
        for (caller, id, status, expected) in [
            (
                &w.carol,
                request.clone(),
                StatusCode::BAD_REQUEST,
                refusal(
                    "invalid_request",
                    &format!("Not authorised to {verb} this request"),
                ),
            ),
            (
                &w.alice,
                own_request.clone(),
                StatusCode::BAD_REQUEST,
                refusal("invalid_request", "Not an incoming friend request"),
            ),
            (
                &w.bob,
                unknown.to_string(),
                StatusCode::NOT_FOUND,
                refusal("not_found", "Friend request not found"),
            ),
        ] {
            assert_eq!(
                w.app
                    .call(
                        method.clone(),
                        &format!("/api/friends/{id}/{verb}"),
                        Some(caller.id),
                        None
                    )
                    .await,
                (status, expected),
                "{verb} by {}",
                caller.username
            );
        }
    }
}

#[tokio::test]
async fn a_declined_request_answers_204_and_leaves_the_incoming_list() {
    let w = world();
    let request = w.incoming_id(&w.alice, &w.bob).await;

    let (status, _) = w
        .app
        .call(
            Method::DELETE,
            &format!("/api/friends/{request}/reject"),
            Some(w.bob.id),
            None,
        )
        .await;

    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        w.app
            .call(Method::GET, "/api/friends/incoming", Some(w.bob.id), None)
            .await,
        (StatusCode::OK, json!([]))
    );
}

#[tokio::test]
async fn unfriending_answers_204_then_404_once_they_are_no_longer_friends() {
    let w = world();
    let request = w.incoming_id(&w.alice, &w.bob).await;
    w.app
        .call(
            Method::POST,
            &format!("/api/friends/{request}/accept"),
            Some(w.bob.id),
            None,
        )
        .await;
    let bob = format!(
        "/api/friends/{}",
        w.bob
            .actor_uri
            .as_str()
            .replace(':', "%3A")
            .replace('/', "%2F")
    );

    let (status, _) = w
        .app
        .call(Method::DELETE, &bob, Some(w.alice.id), None)
        .await;

    assert_eq!(status, StatusCode::NO_CONTENT);
    for path in [bob.as_str(), "/api/friends/not-an-actor"] {
        assert_eq!(
            w.app
                .call(Method::DELETE, path, Some(w.alice.id), None)
                .await,
            (
                StatusCode::NOT_FOUND,
                refusal("not_found", "Friendship not found")
            ),
            "{path}"
        );
    }
}

#[tokio::test]
async fn a_peer_the_url_policy_refuses_is_a_403() {
    let refused = ApiError::from(SocialError::PeerNotAllowed("private address".into()));

    let (status, body) = TestApp::body_of(refused).await;

    assert_eq!(
        (status, body),
        (
            StatusCode::FORBIDDEN,
            refusal("access_denied", "private address")
        )
    );
}

#[tokio::test]
async fn a_request_to_someone_the_caller_blocked_is_refused() {
    let w = world();
    w.app.reach.set(w.alice.id, &w.bob.actor_uri, BLOCKED);

    assert_eq!(
        w.request(&w.alice, &w.bob.username).await,
        (
            StatusCode::BAD_REQUEST,
            refusal("invalid_request", "Unblock this user first")
        )
    );
}

/// Alice's answer is any request's: nothing in it tells her Bob blocked her.
#[tokio::test]
async fn a_request_to_someone_who_blocked_the_caller_is_answered_as_any_other() {
    let w = world();
    w.app.reach.set(w.bob.id, &w.alice.actor_uri, BLOCKED);

    let (status, body) = w.request(&w.alice, &w.bob.username).await;
    let (_, unblocked) = w.request(&w.carol, &w.bob.username).await;

    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["status"], unblocked["status"]);
    let (_, incoming) = w
        .app
        .call(Method::GET, "/api/friends/incoming", Some(w.bob.id), None)
        .await;
    let from: Vec<_> = incoming
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["actor_uri"].clone())
        .collect();
    assert_eq!(from, vec![json!(w.carol.actor_uri.as_str())]);
}

#[tokio::test]
async fn a_request_to_an_instance_that_does_not_answer_is_a_bad_gateway() {
    let alice = account("alice");
    let app = TestApp::knowing(
        [alice.clone()],
        InMemoryRemoteActors::default().and_down("idp.down.test"),
    );

    let answer = app
        .call(
            Method::POST,
            "/api/friends/request",
            Some(alice.id),
            Some(json!({ "address": "dave_k2m9x@idp.down.test" })),
        )
        .await;

    assert_eq!(
        answer,
        (
            StatusCode::BAD_GATEWAY,
            refusal("bad_gateway", "the account's instance did not answer")
        )
    );
}
