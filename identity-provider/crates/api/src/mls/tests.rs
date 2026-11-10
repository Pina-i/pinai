use axum::http::Method;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use domain::e2ee::testing;
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

    fn group_info(&self) -> String {
        format!("/api/mls/groups/{}/group-info", self.group)
    }

    async fn commit(&self, by: &Account, epoch: i64, blob: &str) -> (StatusCode, Value) {
        self.commit_with_info(by, epoch, blob, &B64.encode([epoch as u8; 4]))
            .await
    }

    async fn commit_with_info(
        &self,
        by: &Account,
        epoch: i64,
        blob: &str,
        group_info: &str,
    ) -> (StatusCode, Value) {
        self.app
            .call(
                Method::POST,
                &self.commits(),
                Some(by.id),
                Some(json!({ "epoch": epoch, "commit_blob": blob, "group_info": group_info })),
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

    let (status, body) = w.commit(&w.alice, 1, &member_commit(1)).await;

    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["conversation_id"], json!(w.group));
    assert_eq!(body["epoch"], 1);
    assert_eq!(
        body["proposer_actor_uri"],
        json!(w.alice.actor_uri.to_string())
    );
    assert_eq!(body["commit_blob"], json!(member_commit(1)));
    assert!(body["id"].as_str().unwrap().parse::<Uuid>().is_ok());
    assert!(body["created_at"].is_string());
}

#[tokio::test]
async fn a_commit_at_a_taken_epoch_answers_409_with_the_winning_commit() {
    let w = world().await;
    let (_, winner) = w.commit(&w.alice, 1, &member_commit(1)).await;

    let (status, body) = w.commit(&w.bob, 1, &member_commit(2)).await;

    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"], "epoch_conflict");
    assert_eq!(
        body["error_description"],
        "another commit already exists at epoch 1 for this conversation"
    );
    assert_eq!(body["winning_commit"], winner);
}

#[tokio::test]
async fn a_commit_past_the_next_epoch_answers_409_with_the_next_one() {
    let w = world().await;
    w.commit(&w.alice, 1, &member_commit(1)).await;

    let (status, body) = w.commit(&w.bob, 3, &member_commit(3)).await;

    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(
        body,
        json!({
            "error": "epoch_not_next",
            "error_description": "this conversation's next commit goes at epoch 2",
            "next_epoch": 2,
        })
    );
}

#[tokio::test]
async fn a_malformed_commit_is_refused() {
    let w = world().await;

    for ((epoch, blob, group_info), description) in [
        ((1, "%%", "AQID"), "`commit_blob` is not valid base64"),
        ((1, "", "AQID"), "`commit_blob` is empty"),
        ((1, "AQID", "%%"), "`group_info` is not valid base64"),
        ((1, "AQID", ""), "`group_info` is empty"),
        ((-1, "AQID", "AQID"), "`epoch` must be non-negative"),
    ] {
        assert_eq!(
            w.commit_with_info(&w.alice, epoch, blob, group_info).await,
            (
                StatusCode::BAD_REQUEST,
                refusal("invalid_request", description)
            )
        );
    }
}

#[tokio::test]
async fn a_commit_without_its_group_info_is_refused_and_kept_nowhere() {
    let w = world().await;

    let (status, _) = w
        .app
        .call(
            Method::POST,
            &w.commits(),
            Some(w.alice.id),
            Some(json!({ "epoch": 1, "commit_blob": "AQID" })),
        )
        .await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let (_, log) = w
        .app
        .call(Method::GET, &w.commits(), Some(w.alice.id), None)
        .await;
    assert_eq!(log["commits"], json!([]));
}

#[tokio::test]
async fn a_member_reads_the_group_info_the_latest_commit_left() {
    let w = world().await;
    let before = w
        .app
        .call(Method::GET, &w.group_info(), Some(w.bob.id), None)
        .await;
    w.commit_with_info(&w.alice, 1, &member_commit(1), &B64.encode([1; 6]))
        .await;
    w.commit_with_info(&w.bob, 2, &member_commit(2), &B64.encode([2; 6]))
        .await;

    let read = w
        .app
        .call(Method::GET, &w.group_info(), Some(w.bob.id), None)
        .await;
    let outsider = w
        .app
        .call(Method::GET, &w.group_info(), Some(w.dave.id), None)
        .await;
    let unknown = w
        .app
        .call(
            Method::GET,
            &format!("/api/mls/groups/{}/group-info", Uuid::new_v4()),
            Some(w.bob.id),
            None,
        )
        .await;

    assert_eq!(
        before,
        (
            StatusCode::NOT_FOUND,
            refusal("not_found", "no GroupInfo is held for this conversation")
        )
    );
    assert_eq!(
        read,
        (
            StatusCode::OK,
            json!({ "epoch": 2, "group_info": B64.encode([2; 6]) })
        )
    );
    assert_eq!(
        outsider,
        (
            StatusCode::FORBIDDEN,
            refusal("access_denied", "not a member of this conversation")
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

/// The base64 of `domain::e2ee::testing`'s blobs, as a client posts them.
fn member_commit(byte: u8) -> String {
    B64.encode(testing::member_commit(byte).as_bytes())
}

fn external_commit() -> String {
    B64.encode(testing::external_commit().as_bytes())
}

#[tokio::test]
async fn only_a_commit_a_client_makes_is_taken() {
    let w = world().await;

    for blob in [
        B64.encode(testing::join_proposal().as_bytes()),
        "AQID".to_owned(),
    ] {
        assert_eq!(
            w.commit(&w.alice, 1, &blob).await,
            (
                StatusCode::BAD_REQUEST,
                refusal("invalid_request", "`commit_blob` is not an MLS commit")
            ),
            "{blob}"
        );
    }
    let (_, log) = w
        .app
        .call(Method::GET, &w.commits(), Some(w.alice.id), None)
        .await;
    assert_eq!(log["commits"], json!([]));
}

#[tokio::test]
async fn an_external_commit_takes_a_session_naming_a_device_approved() {
    let w = world().await;
    let (session, laptop) = w.app.on_a_device(w.alice.id).await;
    let on_the_laptop = w.app.token_in(w.alice.id, session);
    w.app.keyed_from(&w.alice, &on_the_laptop, laptop).await;
    let (fresh, _) = w.app.on_a_device(w.alice.id).await;
    let on_the_fresh_one = w.app.token_in(w.alice.id, fresh);
    let unnamed = w.app.token(w.alice.id);
    let body = json!({ "epoch": 1, "commit_blob": external_commit(), "group_info": "AQID" });
    let uri = w.commits();
    let mut answers = Vec::new();
    for token in [&on_the_fresh_one, &unnamed, &on_the_laptop] {
        answers.push(
            w.app
                .call_in(token, Method::POST, &uri, Some(body.clone()))
                .await,
        );
    }
    let [from_the_fresh_one, from_no_device, (status, committed)] =
        <[_; 3]>::try_from(answers).unwrap();

    assert_eq!(
        from_the_fresh_one,
        (
            StatusCode::FORBIDDEN,
            refusal(
                "approval_required",
                "This takes a device approved under the current history key"
            )
        )
    );
    assert_eq!(
        from_no_device,
        (
            StatusCode::FORBIDDEN,
            refusal("device_required", "Name this session's device first")
        )
    );
    assert_eq!(status, StatusCode::CREATED, "{committed}");
    assert_eq!(committed["epoch"], 1, "the refusals took no epoch");
}

#[tokio::test]
async fn a_members_commit_takes_no_device() {
    let w = world().await;
    let (session, laptop) = w.app.on_a_device(w.alice.id).await;
    w.app
        .keyed_from(&w.alice, &w.app.token_in(w.alice.id, session), laptop)
        .await;

    let (status, body) = w.commit(&w.alice, 1, &member_commit(1)).await;

    assert_eq!(status, StatusCode::CREATED, "{body}");
}

#[tokio::test]
async fn a_non_members_commit_is_forbidden() {
    let w = world().await;

    assert_eq!(
        w.commit(&w.dave, 1, &member_commit(1)).await,
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
        w.commit(&w.alice, epoch, &member_commit(epoch as u8)).await;
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
        (Method::GET, w.group_info()),
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
            Some(json!({
                "epoch": 1,
                "commit_blob": member_commit(1),
                "group_info": "AQID",
            })),
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
