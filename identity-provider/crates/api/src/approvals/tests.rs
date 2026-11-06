use axum::body::Body;
use axum::http::{Method, Request, header};
use domain::e2ee::testing::plain_signature;
use domain::e2ee::{DeviceRootKey, approval_bytes};
use domain::identity::Account;
use domain::identity::testing::account;
use serde_json::{Value, json};
use time::format_description::well_known::Rfc3339;

use crate::testing::TestApp;

use super::*;

struct World {
    app: TestApp,
    alice: Account,
    bob: Account,
}

fn world() -> World {
    let (alice, bob) = (account("alice"), account("bob"));
    World {
        app: TestApp::with([alice.clone(), bob.clone()], []),
        alice,
        bob,
    }
}

fn refusal(code: &str, description: &str) -> Value {
    json!({ "error": code, "error_description": description })
}

/// Every device `TestApp::on_a_device` registers has this root key.
fn root_key() -> DeviceRootKey {
    DeviceRootKey::parse(&[7; 32]).unwrap()
}

/// What `signer` signs to approve `who`'s `device`, standard base64.
fn signed(signer: &dyn domain::e2ee::Ed25519PublicKey, who: &Account, device: Uuid) -> String {
    let bytes = approval_bytes(&who.actor_uri, device.into(), &root_key());
    B64.encode(plain_signature(signer, &bytes).as_bytes())
}

impl World {
    /// A token of a session of `who`'s that named a new device of theirs, and the device.
    async fn on_a_device(&self, who: &Account) -> (String, Uuid) {
        let (session, device) = self.app.on_a_device(who.id).await;
        (self.app.token_in(who.id, session), device)
    }

    async fn approve(&self, token: &str, device: Uuid, body: Value) -> (StatusCode, Value) {
        self.app
            .call_in(
                token,
                Method::POST,
                &format!("/api/keys/devices/{device}/approvals"),
                Some(body),
            )
            .await
    }

    /// The approvals listed with `device`.
    async fn approvals_of(&self, who: &Account, device: Uuid) -> Value {
        let (status, body) = self
            .app
            .call(Method::GET, "/api/keys/devices", Some(who.id), None)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["devices"]
            .as_array()
            .unwrap()
            .iter()
            .find(|d| d["device_id"] == json!(device))
            .expect("listed")["approvals"]
            .clone()
    }

    async fn history_key(&self, token: &str, approval_key: [u8; 32]) {
        let (status, body) = self
            .app
            .call_in(
                token,
                Method::PUT,
                "/api/history/key",
                Some(json!({
                    "generation": 1,
                    "salt": B64.encode([1; 16]),
                    "check_value": B64.encode([2; 32]),
                    "approval_public_key": B64.encode(approval_key),
                })),
            )
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    }

    async fn open(&self, token: &str) -> (StatusCode, Value) {
        self.app
            .call_in(
                token,
                Method::POST,
                "/api/keys/devices/approval-requests",
                None,
            )
            .await
    }

    async fn opened(&self, token: &str) -> Uuid {
        let (status, body) = self.open(token).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        body["id"].as_str().unwrap().parse().unwrap()
    }

    async fn post(&self, token: &str, request: Uuid, body: &[u8]) -> (StatusCode, Value) {
        self.app
            .call_in(
                token,
                Method::POST,
                &format!("/api/keys/devices/approval-requests/{request}/messages"),
                Some(json!({ "body": B64.encode(body) })),
            )
            .await
    }

    async fn read(&self, token: &str, request: Uuid, after: &str) -> (StatusCode, Value) {
        self.app
            .call_in(
                token,
                Method::GET,
                &format!("/api/keys/devices/approval-requests/{request}/messages{after}"),
                None,
            )
            .await
    }

    async fn close(&self, token: &str, request: Uuid) -> (StatusCode, Value) {
        self.app
            .call_in(
                token,
                Method::DELETE,
                &format!("/api/keys/devices/approval-requests/{request}"),
                None,
            )
            .await
    }
}

#[tokio::test]
async fn a_device_approves_another_and_the_list_carries_the_signature() {
    let w = world();
    let (laptops, laptop) = w.on_a_device(&w.alice).await;
    let (_, phone) = w.on_a_device(&w.alice).await;
    let signature = signed(&root_key(), &w.alice, phone);

    let approved = w
        .approve(
            &laptops,
            phone,
            json!({ "by": "device", "signature": signature }),
        )
        .await;
    let again = w
        .approve(
            &laptops,
            phone,
            json!({ "by": "device", "signature": signature }),
        )
        .await;

    assert_eq!(approved, (StatusCode::NO_CONTENT, Value::Null));
    assert_eq!(again, (StatusCode::NO_CONTENT, Value::Null));
    let approvals = w.approvals_of(&w.alice, phone).await;
    assert_eq!(approvals.as_array().unwrap().len(), 1);
    let created_at = approvals[0]["created_at"].as_str().unwrap();
    assert!(
        OffsetDateTime::parse(created_at, &Rfc3339).is_ok(),
        "{created_at}"
    );
    assert_eq!(
        approvals[0],
        json!({
            "by": "device",
            "device_id": laptop,
            "signature": signature,
            "created_at": created_at,
        })
    );
    assert_eq!(w.approvals_of(&w.alice, laptop).await, json!([]));
}

#[tokio::test]
async fn the_passphrase_approves_the_sessions_device_and_the_list_names_the_generation() {
    let w = world();
    let (laptops, laptop) = w.on_a_device(&w.alice).await;
    let approval_key = [40; 32];
    w.history_key(&laptops, approval_key).await;
    let signature = signed(
        &DeviceRootKey::parse(&approval_key).unwrap(),
        &w.alice,
        laptop,
    );

    let approved = w
        .approve(
            &laptops,
            laptop,
            json!({ "by": "passphrase", "generation": 1, "signature": signature }),
        )
        .await;

    assert_eq!(approved, (StatusCode::NO_CONTENT, Value::Null));
    let approvals = w.approvals_of(&w.alice, laptop).await;
    assert_eq!(approvals[0]["by"], "passphrase");
    assert_eq!(approvals[0]["generation"], 1);
    assert_eq!(approvals[0]["signature"], json!(signature));
    assert!(approvals[0].get("device_id").is_none());
}

#[tokio::test]
async fn a_malformed_approval_is_refused_before_anything_is_checked() {
    let w = world();
    let (laptops, laptop) = w.on_a_device(&w.alice).await;
    let signature = signed(&root_key(), &w.alice, laptop);

    for (body, description) in [
        (
            json!({ "by": "magic", "signature": signature }),
            "by must be 'device' or 'passphrase'",
        ),
        (
            json!({ "by": "device", "generation": 1, "signature": signature }),
            "generation comes with by: passphrase only",
        ),
        (
            json!({ "by": "passphrase", "signature": signature }),
            "generation is required with by: passphrase",
        ),
        (
            json!({ "by": "passphrase", "generation": 0, "signature": signature }),
            "generation: must be from 1 to 2147483647",
        ),
        (
            json!({ "by": "device", "signature": "not base64!" }),
            "signature: must be base64",
        ),
        (
            json!({ "by": "device", "signature": B64.encode([1; 63]) }),
            "signature: must be 64 bytes (Ed25519)",
        ),
    ] {
        assert_eq!(
            w.approve(&laptops, laptop, body.clone()).await,
            (
                StatusCode::BAD_REQUEST,
                refusal("invalid_request", description)
            ),
            "{body}"
        );
    }
}

#[tokio::test]
async fn an_approval_is_refused_with_the_documented_errors() {
    let w = world();
    let (laptops, laptop) = w.on_a_device(&w.alice).await;
    let (_, phone) = w.on_a_device(&w.alice).await;
    let (_, bobs) = w.on_a_device(&w.bob).await;
    let unnamed = w.app.token(w.alice.id);
    let by_device = |signature: String| json!({ "by": "device", "signature": signature });
    let by_words =
        |signature: String| json!({ "by": "passphrase", "generation": 1, "signature": signature });

    let from_unnamed = w
        .approve(
            &unnamed,
            phone,
            by_device(signed(&root_key(), &w.alice, phone)),
        )
        .await;
    let forged = w
        .approve(
            &laptops,
            phone,
            by_device(signed(
                &DeviceRootKey::parse(&[9; 32]).unwrap(),
                &w.alice,
                phone,
            )),
        )
        .await;
    let itself = w
        .approve(
            &laptops,
            laptop,
            by_device(signed(&root_key(), &w.alice, laptop)),
        )
        .await;
    let anothers = w
        .approve(
            &laptops,
            bobs,
            by_device(signed(&root_key(), &w.alice, bobs)),
        )
        .await;
    let words_for_another = w
        .approve(
            &laptops,
            phone,
            by_words(signed(&root_key(), &w.alice, phone)),
        )
        .await;
    let words_before_a_key = w
        .approve(
            &laptops,
            laptop,
            by_words(signed(&root_key(), &w.alice, laptop)),
        )
        .await;

    assert_eq!(
        from_unnamed,
        (
            StatusCode::FORBIDDEN,
            refusal("device_required", "Name this session's device first")
        )
    );
    assert_eq!(
        forged,
        (
            StatusCode::BAD_REQUEST,
            refusal(
                "invalid_request",
                "signature does not verify over the device's root key"
            )
        )
    );
    assert_eq!(
        itself,
        (
            StatusCode::BAD_REQUEST,
            refusal(
                "invalid_request",
                "A device approves itself with the passphrase only"
            )
        )
    );
    assert_eq!(
        anothers,
        (
            StatusCode::NOT_FOUND,
            refusal("not_found", "Device not found")
        )
    );
    assert_eq!(
        words_for_another,
        (
            StatusCode::FORBIDDEN,
            refusal("device_mismatch", "This session signed in another device")
        )
    );
    assert_eq!(
        words_before_a_key,
        (
            StatusCode::CONFLICT,
            refusal("stale_history_key", "Not the account's current history key")
        )
    );
}

#[tokio::test]
async fn a_device_without_a_root_key_is_neither_approved_nor_asks() {
    let w = world();
    let (laptops, _) = w.on_a_device(&w.alice).await;
    let unattested = Uuid::new_v4();
    let in_a_week = (OffsetDateTime::now_utc() + time::Duration::days(7))
        .format(&Rfc3339)
        .unwrap();
    let session = w.app.sign_in.sessions.live(w.alice.id);
    let unattesteds = w.app.token_in(w.alice.id, session);
    let (stashed, body) = w
        .app
        .call_in(
            &unattesteds,
            Method::POST,
            "/api/keys/packages",
            Some(json!({
                "device_id": unattested,
                "packages": [{ "key_package": B64.encode([1; 8]), "expires_at": in_a_week }],
            })),
        )
        .await;
    assert!(stashed.is_success(), "{body}");
    let proof = w.app.naming_proof(w.alice.id, session, unattested).await;
    let named = w
        .app
        .call_in(
            &unattesteds,
            Method::PUT,
            "/api/sessions/current/device",
            Some(json!({ "device_id": unattested, "signature": proof })),
        )
        .await;

    let approved = w
        .approve(
            &laptops,
            unattested,
            json!({ "by": "device", "signature": B64.encode([1; 64]) }),
        )
        .await;
    let asked = w.open(&unattesteds).await;

    assert_eq!(
        named,
        (
            StatusCode::FORBIDDEN,
            refusal(
                "device_proof_invalid",
                "The signature does not prove this device's root key"
            )
        ),
        "no root key, nothing to prove with"
    );
    assert_eq!(
        approved,
        (
            StatusCode::CONFLICT,
            refusal("no_root_key", "The device has registered no root key"),
        )
    );
    assert_eq!(
        asked,
        (
            StatusCode::FORBIDDEN,
            refusal("device_required", "Name this session's device first"),
        )
    );
}

#[tokio::test]
async fn a_request_is_opened_listed_relayed_and_closed() {
    let w = world();
    let (laptops, laptop) = w.on_a_device(&w.alice).await;
    let (phones, phone) = w.on_a_device(&w.alice).await;

    let (opened, request) = w.open(&laptops).await;
    let id: Uuid = request["id"].as_str().unwrap().parse().unwrap();
    let (listed, requests) = w
        .app
        .call_in(
            &phones,
            Method::GET,
            "/api/keys/devices/approval-requests",
            None,
        )
        .await;
    let asked = w.post(&laptops, id, b"spake2 A").await;
    let answered = w.post(&phones, id, b"spake2 B").await;
    let (read, for_laptop) = w.read(&laptops, id, "").await;
    let (read_after, after_first) = w.read(&phones, id, "?after=1").await;
    let closed = w.close(&phones, id).await;
    let after_closing = w.post(&laptops, id, b"too late").await;

    assert_eq!(opened, StatusCode::CREATED);
    let expires_at =
        OffsetDateTime::parse(request["expires_at"].as_str().unwrap(), &Rfc3339).unwrap();
    let ten_minutes = expires_at - OffsetDateTime::now_utc();
    assert!(ten_minutes > time::Duration::minutes(9), "{ten_minutes}");
    assert_eq!(listed, StatusCode::OK);
    let entry = &requests["requests"][0];
    assert_eq!(
        (
            &entry["id"],
            &entry["device_id"],
            &entry["display_name"],
            &entry["approver_device_id"],
            &entry["expires_at"]
        ),
        (
            &json!(id),
            &json!(laptop),
            &json!("Web client"),
            &Value::Null,
            &request["expires_at"]
        )
    );
    assert!(entry["created_at"].is_string());
    assert_eq!(asked, (StatusCode::CREATED, json!({ "seq": 1 })));
    assert_eq!(answered, (StatusCode::CREATED, json!({ "seq": 2 })));
    assert_eq!(read, StatusCode::OK);
    let messages = for_laptop["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(
        (
            &messages[0]["seq"],
            &messages[0]["device_id"],
            &messages[0]["body"]
        ),
        (&json!(2), &json!(phone), &json!(B64.encode(b"spake2 B")))
    );
    assert!(messages[0]["created_at"].is_string());
    assert_eq!(
        (read_after, after_first),
        (StatusCode::OK, json!({ "messages": [] }))
    );
    assert_eq!(closed, (StatusCode::NO_CONTENT, Value::Null));
    assert_eq!(
        after_closing,
        (
            StatusCode::GONE,
            refusal("approval_request_ended", "The approval request has ended")
        )
    );
}

#[tokio::test]
async fn a_request_is_refused_with_the_documented_errors() {
    let w = world();
    let (laptops, _) = w.on_a_device(&w.alice).await;
    let (phones, _) = w.on_a_device(&w.alice).await;
    let (tablets, _) = w.on_a_device(&w.alice).await;
    let (bobs, _) = w.on_a_device(&w.bob).await;
    let unnamed = w.app.token(w.alice.id);
    let id = w.opened(&laptops).await;
    w.post(&phones, id, b"answer").await;
    for _ in 0..11 {
        w.post(&laptops, id, b"more").await;
    }

    let taken = w.post(&tablets, id, b"me too").await;
    let taken_read = w.read(&tablets, id, "").await;
    let full = w.post(&phones, id, b"thirteenth").await;
    let anothers = w.read(&bobs, id, "").await;
    let unknown = w.close(&laptops, Uuid::new_v4()).await;
    let too_large = w.post(&laptops, id, &[1; 4097]).await;
    let empty = w.post(&laptops, id, b"").await;
    let bad_after = w.read(&laptops, id, "?after=-1").await;
    let from_unnamed = w.open(&unnamed).await;

    let taken_refusal = (
        StatusCode::CONFLICT,
        refusal(
            "approval_request_taken",
            "Another device is answering this approval request",
        ),
    );
    assert_eq!(taken, taken_refusal);
    assert_eq!(taken_read, taken_refusal);
    assert_eq!(
        full,
        (
            StatusCode::CONFLICT,
            refusal(
                "approval_request_full",
                "The approval request holds no more messages"
            )
        )
    );
    let not_found = (
        StatusCode::NOT_FOUND,
        refusal("not_found", "Approval request not found"),
    );
    assert_eq!(anothers, not_found);
    assert_eq!(unknown, not_found);
    let too_big = (
        StatusCode::BAD_REQUEST,
        refusal("invalid_request", "body: must be 1 to 4096 bytes"),
    );
    assert_eq!(too_large, too_big);
    assert_eq!(empty, too_big);
    assert_eq!(
        bad_after,
        (
            StatusCode::BAD_REQUEST,
            refusal("invalid_request", "after: must be from 0 to 2147483647")
        )
    );
    assert_eq!(
        from_unnamed,
        (
            StatusCode::FORBIDDEN,
            refusal("device_required", "Name this session's device first")
        )
    );
}

#[tokio::test]
async fn the_eleventh_request_in_an_hour_is_too_many() {
    let w = world();
    let (laptops, _) = w.on_a_device(&w.alice).await;
    for _ in 0..10 {
        w.opened(&laptops).await;
    }

    let eleventh = w.open(&laptops).await;

    assert_eq!(
        eleventh,
        (
            StatusCode::TOO_MANY_REQUESTS,
            refusal(
                "too_many_requests",
                "Too many approval requests in the last hour"
            )
        )
    );
}

#[tokio::test]
async fn the_approval_routes_need_a_signed_in_user() {
    let w = world();
    let id = Uuid::new_v4();

    for (method, uri) in [
        (Method::POST, format!("/api/keys/devices/{id}/approvals")),
        (
            Method::GET,
            "/api/keys/devices/approval-requests".to_owned(),
        ),
        (
            Method::POST,
            "/api/keys/devices/approval-requests".to_owned(),
        ),
        (
            Method::DELETE,
            format!("/api/keys/devices/approval-requests/{id}"),
        ),
        (
            Method::GET,
            format!("/api/keys/devices/approval-requests/{id}/messages"),
        ),
        (
            Method::POST,
            format!("/api/keys/devices/approval-requests/{id}/messages"),
        ),
    ] {
        let (status, _) = w.app.call(method.clone(), &uri, None, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {uri}");
    }
}

#[tokio::test]
async fn an_ended_request_is_gone_for_all_but_its_two_sides() {
    let w = world();
    let (laptops, laptop) = w.on_a_device(&w.alice).await;
    let (phones, _) = w.on_a_device(&w.alice).await;
    let unanswered = w.opened(&laptops).await;
    let answered = w.opened(&phones).await;
    w.post(&laptops, answered, b"answer").await;
    w.close(&laptops, unanswered).await;
    w.close(&laptops, answered).await;

    let (read, after_closing) = w.read(&phones, answered, "").await;

    let ended = (
        StatusCode::GONE,
        refusal("approval_request_ended", "The approval request has ended"),
    );
    assert_eq!(w.read(&phones, unanswered, "").await, ended);
    assert_eq!(w.close(&laptops, unanswered).await, ended);
    assert_eq!(w.post(&phones, answered, b"late").await, ended);
    assert_eq!(
        read,
        StatusCode::OK,
        "the asking device still reads the answer"
    );
    let messages = after_closing["messages"].as_array().unwrap();
    assert_eq!(
        (&messages[0]["device_id"], &messages[0]["body"]),
        (&json!(laptop), &json!(B64.encode(b"answer")))
    );
}

#[tokio::test]
async fn a_revoked_device_is_not_approved() {
    let w = world();
    let (laptops, _) = w.on_a_device(&w.alice).await;
    let (_, phone) = w.on_a_device(&w.alice).await;
    let (revoked, body) = w
        .app
        .call(
            Method::POST,
            &format!("/api/keys/devices/{phone}/revoke"),
            Some(w.alice.id),
            None,
        )
        .await;
    assert_eq!(revoked, StatusCode::NO_CONTENT, "{body}");

    let approved = w
        .approve(
            &laptops,
            phone,
            json!({ "by": "device", "signature": signed(&root_key(), &w.alice, phone) }),
        )
        .await;

    assert_eq!(
        approved,
        (
            StatusCode::FORBIDDEN,
            refusal("access_denied", "Device is revoked")
        )
    );
}

#[tokio::test]
async fn a_request_names_its_device_as_its_first_registration_said() {
    let w = world();
    let session = w.app.sign_in.sessions.live(w.alice.id);
    let token = w.app.token_in(w.alice.id, session);
    let device = Uuid::new_v4();
    let registration = Request::builder()
        .method(Method::POST)
        .uri("/api/keys/devices")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(
            header::USER_AGENT,
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/130.0 Safari/537.36",
        )
        .body(Body::from(
            json!({ "device_id": device, "drk_public_key": B64.encode([7; 32]) }).to_string(),
        ))
        .unwrap();
    let (registered, body) = w.app.send(registration).await;
    assert_eq!(registered, StatusCode::CREATED, "{body}");
    let (named, body) = w
        .app
        .call_in(
            &token,
            Method::PUT,
            "/api/sessions/current/device",
            Some(json!({
                "device_id": device,
                "signature": w.app.naming_proof(w.alice.id, session, device).await,
            })),
        )
        .await;
    assert_eq!(named, StatusCode::NO_CONTENT, "{body}");
    w.opened(&token).await;

    let (_, requests) = w
        .app
        .call_in(
            &token,
            Method::GET,
            "/api/keys/devices/approval-requests",
            None,
        )
        .await;

    assert_eq!(requests["requests"][0]["display_name"], "Chrome on Linux");
}
