use axum::http::Method;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use domain::identity::testing::{account, remote_actor};
use domain::identity::{Account, RemoteActor};
use serde_json::{Value, json};

use domain::social::testing::KEPT_OUT_BY_THE_SETTING;

use crate::testing::TestApp;

use super::*;

struct World {
    app: TestApp,
    alice: Account,
    bob: Account,
    dave: Account,
    carol: RemoteActor,
    group: String,
}

async fn world() -> World {
    let (alice, bob, dave) = (account("alice"), account("bob"), account("dave"));
    let carol = remote_actor("carol_k2m9x@idp.carol.test");
    let app = TestApp::with([alice.clone(), bob.clone(), dave.clone()], [carol.clone()]);
    let (status, group) = app
        .call(
            Method::POST,
            "/api/groups",
            Some(alice.id),
            Some(json!({
                "name": "crew",
                "member_actor_uris": [bob.actor_uri.to_string(), carol.actor_uri.to_string()],
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{group}");
    World {
        group: group["conversationId"].as_str().unwrap().to_owned(),
        app,
        alice,
        bob,
        dave,
        carol,
    }
}

fn refusal(code: &str, description: &str) -> Value {
    json!({ "error": code, "error_description": description })
}

impl World {
    fn commits(&self) -> String {
        format!("/api/mls/groups/{}/commits", self.group)
    }

    async fn commit(&self, by: &Account, epoch: i64, blob: &str) -> (StatusCode, Value) {
        self.app
            .call(
                Method::POST,
                &self.commits(),
                Some(by.id),
                Some(json!({ "epoch": epoch, "commit_blob": blob })),
            )
            .await
    }

    async fn welcome(
        &self,
        from: &Account,
        to: &str,
        device: Uuid,
        blob: &str,
    ) -> (StatusCode, Value) {
        self.app
            .call(
                Method::POST,
                "/api/mls/welcomes",
                Some(from.id),
                Some(json!({
                    "recipient_actor_uri": to,
                    "recipient_device_id": device,
                    "conversation_id": self.group,
                    "welcome_blob": blob,
                })),
            )
            .await
    }
}

#[tokio::test]
async fn a_members_commit_answers_201_with_the_stored_commit() {
    let w = world().await;

    let (status, body) = w.commit(&w.alice, 1, &B64.encode([1; 8])).await;

    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["conversation_id"], json!(w.group));
    assert_eq!(body["epoch"], 1);
    assert_eq!(
        body["proposer_actor_uri"],
        json!(w.alice.actor_uri.to_string())
    );
    assert_eq!(body["commit_blob"], json!(B64.encode([1; 8])));
    assert!(body["id"].as_str().unwrap().parse::<Uuid>().is_ok());
    assert!(body["created_at"].is_string());
}

#[tokio::test]
async fn a_commit_at_a_taken_epoch_answers_409_with_the_winning_commit() {
    let w = world().await;
    let (_, winner) = w.commit(&w.alice, 2, &B64.encode([1; 8])).await;

    let (status, body) = w.commit(&w.bob, 2, &B64.encode([2; 8])).await;

    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"], "epoch_conflict");
    assert_eq!(
        body["error_description"],
        "another commit already exists at epoch 2 for this conversation"
    );
    assert_eq!(body["winning_commit"], winner);
}

#[tokio::test]
async fn a_malformed_commit_is_refused() {
    let w = world().await;

    for ((epoch, blob), description) in [
        ((1, "%%"), "`commit_blob` is not valid base64"),
        ((1, ""), "`commit_blob` is empty"),
        ((-1, "AQID"), "`epoch` must be non-negative"),
    ] {
        assert_eq!(
            w.commit(&w.alice, epoch, blob).await,
            (
                StatusCode::BAD_REQUEST,
                refusal("invalid_request", description)
            )
        );
    }
}

#[tokio::test]
async fn a_non_members_commit_is_forbidden() {
    let w = world().await;

    assert_eq!(
        w.commit(&w.dave, 1, &B64.encode([1; 8])).await,
        (
            StatusCode::FORBIDDEN,
            refusal("access_denied", "not a member of this conversation")
        )
    );
}

#[tokio::test]
async fn a_member_catches_up_after_an_epoch() {
    let w = world().await;
    for epoch in 1..=3 {
        w.commit(&w.alice, epoch, &B64.encode([epoch as u8; 8]))
            .await;
    }

    let (status, body) = w
        .app
        .call(
            Method::GET,
            &format!("{}?since=1", w.commits()),
            Some(w.bob.id),
            None,
        )
        .await;
    let negative = w
        .app
        .call(
            Method::GET,
            &format!("{}?since=-1", w.commits()),
            Some(w.bob.id),
            None,
        )
        .await;
    let unknown = w
        .app
        .call(
            Method::GET,
            &format!("/api/mls/groups/{}/commits", Uuid::new_v4()),
            Some(w.bob.id),
            None,
        )
        .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    let epochs: Vec<&Value> = body["commits"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| &c["epoch"])
        .collect();
    assert_eq!(epochs, vec![&json!(2), &json!(3)]);
    assert_eq!(body["has_more"], false);
    assert_eq!(
        negative,
        (
            StatusCode::BAD_REQUEST,
            refusal("invalid_request", "`since` must be non-negative")
        )
    );
    assert_eq!(
        unknown,
        (
            StatusCode::NOT_FOUND,
            refusal("not_found", "conversation not found")
        )
    );
}

#[tokio::test]
async fn a_welcome_for_a_local_member_is_fetched_by_its_device() {
    let w = world().await;
    let device = Uuid::new_v4();

    let (status, sent) = w
        .welcome(
            &w.alice,
            &w.bob.actor_uri.to_string(),
            device,
            &B64.encode([4; 8]),
        )
        .await;
    let (_, fetched) = w
        .app
        .call(
            Method::GET,
            &format!("/api/mls/welcomes?device_id={device}"),
            Some(w.bob.id),
            None,
        )
        .await;
    let (_, again) = w
        .app
        .call(
            Method::GET,
            &format!("/api/mls/welcomes?device_id={device}"),
            Some(w.bob.id),
            None,
        )
        .await;

    assert_eq!(status, StatusCode::OK, "{sent}");
    let welcomes = fetched["welcomes"].as_array().unwrap();
    assert_eq!(welcomes.len(), 1);
    assert_eq!(welcomes[0]["id"], sent["id"]);
    assert_eq!(
        (
            &welcomes[0]["conversation_id"],
            &welcomes[0]["recipient_device_id"]
        ),
        (&json!(w.group), &json!(device))
    );
    assert_eq!(welcomes[0]["welcome_blob"], json!(B64.encode([4; 8])));
    assert!(welcomes[0]["created_at"].is_string());
    assert_eq!(again, json!({ "welcomes": [] }));
}

#[tokio::test]
async fn a_welcome_for_a_remote_member_answers_a_nil_id() {
    let w = world().await;

    let sent = w
        .welcome(
            &w.alice,
            &w.carol.actor_uri.to_string(),
            Uuid::new_v4(),
            &B64.encode([4; 8]),
        )
        .await;

    assert_eq!(sent, (StatusCode::OK, json!({ "id": Uuid::nil() })));
}

#[tokio::test]
async fn a_malformed_welcome_or_an_unknown_local_recipient_is_refused() {
    let w = world().await;
    let bob = w.bob.actor_uri.to_string();

    for ((to, blob), expected) in [
        (
            (bob.as_str(), "%%"),
            (
                StatusCode::BAD_REQUEST,
                refusal("invalid_request", "`welcome_blob` is not valid base64"),
            ),
        ),
        (
            (bob.as_str(), ""),
            (
                StatusCode::BAD_REQUEST,
                refusal("invalid_request", "`welcome_blob` is empty"),
            ),
        ),
        (
            ("not a uri", "AQID"),
            (
                StatusCode::BAD_REQUEST,
                refusal("invalid_request", "recipient_actor_uri is not a valid URL"),
            ),
        ),
        (
            ("http://localhost:8080/users/nobody_t3st0", "AQID"),
            (
                StatusCode::NOT_FOUND,
                refusal(
                    "not_found",
                    "recipient_actor_uri matches our issuer but no such user",
                ),
            ),
        ),
    ] {
        assert_eq!(
            w.welcome(&w.alice, to, Uuid::new_v4(), blob).await,
            expected,
            "{to} {blob}"
        );
    }
}

#[tokio::test]
async fn the_delivery_service_needs_a_signed_in_user() {
    let w = world().await;

    for (method, uri) in [
        (Method::GET, w.commits()),
        (
            Method::GET,
            format!("/api/mls/welcomes?device_id={}", Uuid::new_v4()),
        ),
    ] {
        let (status, _) = w.app.call(method, &uri, None, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{uri}");
    }
}

#[tokio::test]
async fn a_welcome_is_handed_out_only_between_members() {
    let w = world().await;
    let (dave, bob) = (w.dave.actor_uri.to_string(), w.bob.actor_uri.to_string());

    let outsider_in = w
        .welcome(&w.alice, &dave, Uuid::new_v4(), &B64.encode([4; 8]))
        .await;
    let from_outside = w
        .welcome(&w.dave, &bob, Uuid::new_v4(), &B64.encode([4; 8]))
        .await;

    assert_eq!(
        outsider_in,
        (
            StatusCode::FORBIDDEN,
            refusal(
                "access_denied",
                "the recipient is not a member of this conversation"
            )
        )
    );
    assert_eq!(
        from_outside,
        (
            StatusCode::FORBIDDEN,
            refusal("access_denied", "not a member of this conversation")
        )
    );
}

#[tokio::test]
async fn a_founding_commit_needs_its_conversation() {
    let w = world().await;

    let founding = w
        .app
        .call(
            Method::POST,
            &format!("/api/mls/groups/{}/commits", Uuid::new_v4()),
            Some(w.alice.id),
            Some(json!({ "epoch": 1, "commit_blob": B64.encode([1; 8]) })),
        )
        .await;

    assert_eq!(
        founding,
        (
            StatusCode::NOT_FOUND,
            refusal("not_found", "conversation not found")
        )
    );
}

#[tokio::test]
async fn a_dms_welcome_to_someone_who_does_not_admit_the_sender_is_refused() {
    let w = world().await;
    let (_, sent) = w
        .app
        .call(
            Method::POST,
            "/api/dm",
            Some(w.alice.id),
            Some(json!({ "recipient_address": w.bob.username, "mls_ciphertext": "AQID" })),
        )
        .await;
    w.app
        .reach
        .set(w.bob.id, &w.alice.actor_uri, KEPT_OUT_BY_THE_SETTING);

    let answer = w
        .app
        .call(
            Method::POST,
            "/api/mls/welcomes",
            Some(w.alice.id),
            Some(json!({
                "recipient_actor_uri": w.bob.actor_uri.to_string(),
                "recipient_device_id": Uuid::new_v4(),
                "conversation_id": sent["conversation_id"],
                "welcome_blob": "AQID",
            })),
        )
        .await;

    assert_eq!(
        answer,
        (
            StatusCode::FORBIDDEN,
            refusal("access_denied", "Can't add this person")
        )
    );
}
