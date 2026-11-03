use axum::http::Method;
use domain::e2ee::testing::plain_signature;
use domain::e2ee::{
    ApprovalPublicKey, DeviceRootKey, Ed25519PublicKey, HpkePublicKey, approval_bytes, share_aad,
    share_signed_bytes,
};
use domain::identity::Account;
use domain::identity::testing::account;
use serde_json::{Value, json};
use time::format_description::well_known::Rfc3339;

use crate::testing::TestApp;

use super::*;

struct World {
    app: TestApp,
    alice: Account,
}

fn world() -> World {
    let alice = account("alice");
    World {
        app: TestApp::with([alice.clone()], []),
        alice,
    }
}

fn refusal(code: &str, description: &str) -> Value {
    json!({ "error": code, "error_description": description })
}

fn root(byte: u8) -> DeviceRootKey {
    DeviceRootKey::parse(&[byte; 32]).unwrap()
}

/// Generation 1's approval key.
fn approval_key() -> ApprovalPublicKey {
    ApprovalPublicKey::parse(&[40; 32]).unwrap()
}

/// A device of Alice's, signed in on a session of its own.
struct Device {
    token: String,
    id: Uuid,
    root: u8,
}

/// The share's seal and its signature by `signer`, in the body's base64.
fn body_for(alice: &Account, signer: u8, sender: Uuid, recipient: Uuid, generation: i64) -> Value {
    let (enc, ciphertext) = (ShareEnc::parse(&[3; 32]).unwrap(), vec![4; 150]);
    let sealed = ShareCiphertext::parse(ciphertext.clone()).unwrap();
    let aad = share_aad(
        &alice.actor_uri,
        sender.into(),
        recipient.into(),
        HistoryGeneration::parse(generation).unwrap(),
    );
    let signature = plain_signature(&root(signer), &share_signed_bytes(&aad, &enc, &sealed));
    json!({
        "recipient_device_id": recipient,
        "generation": generation,
        "enc": B64.encode(enc.as_bytes()),
        "ciphertext": B64.encode(ciphertext),
        "signature": B64.encode(signature.as_bytes()),
    })
}

impl World {
    async fn ok(&self, token: &str, method: Method, uri: &str, body: Value) {
        let (status, answer) = self.app.call_in(token, method, uri, Some(body)).await;
        assert!(status.is_success(), "{uri}: {answer}");
    }

    /// A device whose root key and HPKE key are made of `root`s, its HPKE key sent when `hpke`.
    async fn device(&self, root_byte: u8, hpke: bool) -> Device {
        let session = self.app.sign_in.sessions.live(self.alice.id);
        let token = self.app.token_in(self.alice.id, session);
        let id = Uuid::new_v4();
        let mut register = json!({
            "device_id": id,
            "drk_public_key": B64.encode([root_byte; 32]),
        });
        if hpke {
            let key = HpkePublicKey::parse(&[root_byte; 32]).unwrap();
            let signed = key.canonical_bytes(&self.alice.actor_uri, id.into());
            register["hpke_public_key"] = json!(B64.encode(key.as_bytes()));
            register["hpke_key_signature"] =
                json!(B64.encode(plain_signature(&root(root_byte), &signed).as_bytes()));
        }
        self.ok(&token, Method::POST, "/api/keys/devices", register)
            .await;
        self.ok(
            &token,
            Method::PUT,
            "/api/sessions/current/device",
            json!({ "device_id": id }),
        )
        .await;
        Device {
            token,
            id,
            root: root_byte,
        }
    }

    fn signed(&self, signer: &dyn Ed25519PublicKey, device: &Device) -> String {
        let bytes = approval_bytes(&self.alice.actor_uri, device.id.into(), &root(device.root));
        B64.encode(plain_signature(signer, &bytes).as_bytes())
    }

    /// `device` approved by generation 1's words, and saying it holds them.
    async fn holding(&self, device: &Device) {
        self.ok(
            &device.token,
            Method::POST,
            &format!("/api/keys/devices/{}/approvals", device.id),
            json!({ "by": "passphrase", "generation": 1, "signature": self.signed(&approval_key(), device) }),
        )
        .await;
        self.reporting(device).await;
    }

    /// `device` saying it holds generation 1.
    async fn reporting(&self, device: &Device) {
        self.ok(
            &device.token,
            Method::PUT,
            &format!("/api/keys/devices/{}/history-key", device.id),
            json!({ "generation": 1 }),
        )
        .await;
    }

    /// The laptop, which set generation 1, holds it and is approved by it.
    async fn laptop(&self) -> Device {
        let laptop = self.device(1, true).await;
        self.ok(
            &laptop.token,
            Method::PUT,
            "/api/history/key",
            json!({
                "generation": 1,
                "salt": B64.encode([1; 16]),
                "check_value": B64.encode([2; 32]),
                "approval_public_key": B64.encode(approval_key().as_bytes()),
            }),
        )
        .await;
        self.holding(&laptop).await;
        laptop
    }

    async fn approve(&self, approver: &Device, device: &Device) {
        self.ok(
            &approver.token,
            Method::POST,
            &format!("/api/keys/devices/{}/approvals", device.id),
            json!({ "by": "device", "signature": self.signed(&root(approver.root), device) }),
        )
        .await;
    }

    async fn share(&self, from: &Device, body: Value) -> (StatusCode, Value) {
        self.app
            .call_in(
                &from.token,
                Method::POST,
                "/api/history/key-shares",
                Some(body),
            )
            .await
    }

    async fn share_to(&self, from: &Device, to: &Device) -> (StatusCode, Value) {
        let body = body_for(&self.alice, from.root, from.id, to.id, 1);
        self.share(from, body).await
    }

    async fn held(&self, token: &str) -> (StatusCode, Value) {
        self.app
            .call_in(token, Method::GET, "/api/history/key-shares", None)
            .await
    }
}

#[tokio::test]
async fn a_holder_shares_the_passphrase_and_its_recipient_reads_it() {
    let w = world();
    let laptop = w.laptop().await;
    let phone = w.device(2, true).await;
    w.approve(&laptop, &phone).await;
    let body = body_for(&w.alice, 1, laptop.id, phone.id, 1);

    let shared = w.share(&laptop, body.clone()).await;
    let again = w.share(&laptop, body.clone()).await;
    let (status, held) = w.held(&phone.token).await;

    assert_eq!(shared, (StatusCode::NO_CONTENT, Value::Null));
    assert_eq!(again, (StatusCode::NO_CONTENT, Value::Null));
    assert_eq!(status, StatusCode::OK, "{held}");
    let created_at = held["created_at"].as_str().unwrap();
    assert!(
        OffsetDateTime::parse(created_at, &Rfc3339).is_ok(),
        "{created_at}"
    );
    assert_eq!(
        held,
        json!({
            "sender_device_id": laptop.id,
            "generation": 1,
            "enc": body["enc"],
            "ciphertext": body["ciphertext"],
            "signature": body["signature"],
            "created_at": created_at,
        })
    );
    assert_eq!(
        w.held(&laptop.token).await,
        (
            StatusCode::NOT_FOUND,
            refusal("not_found", "No key share for this device")
        )
    );
}

#[tokio::test]
async fn a_malformed_share_is_refused_before_anything_is_checked() {
    let w = world();
    let laptop = w.laptop().await;
    let phone = w.device(2, true).await;
    let body = body_for(&w.alice, 1, laptop.id, phone.id, 1);
    let with = |field: &str, value: Value| {
        let mut changed = body.clone();
        changed[field] = value;
        changed
    };

    for (malformed, description) in [
        (with("enc", json!("not base64!")), "enc: must be base64"),
        (
            with("enc", json!(B64.encode([3; 31]))),
            "enc: must be 32 bytes (X25519)",
        ),
        (
            with("ciphertext", json!("")),
            "ciphertext: must be 1 to 1024 bytes",
        ),
        (
            with("ciphertext", json!(B64.encode([4; 1025]))),
            "ciphertext: must be 1 to 1024 bytes",
        ),
        (
            with("signature", json!(B64.encode([5; 63]))),
            "signature: must be 64 bytes (Ed25519)",
        ),
        (
            with("generation", json!(0)),
            "generation: must be from 1 to 2147483647",
        ),
    ] {
        assert_eq!(
            w.share(&laptop, malformed.clone()).await,
            (
                StatusCode::BAD_REQUEST,
                refusal("invalid_request", description)
            ),
            "{malformed}"
        );
    }
}

#[tokio::test]
async fn each_refusal_answers_its_status_and_code() {
    let w = world();
    let laptop = w.laptop().await;
    let phone = w.device(2, true).await;
    w.approve(&laptop, &phone).await;
    let unapproved = w.device(3, true).await;
    let without_hpke = w.device(4, false).await;
    w.approve(&laptop, &without_hpke).await;
    let holding = w.device(5, true).await;
    w.holding(&holding).await;
    w.approve(&laptop, &holding).await;
    let not_holding = w.device(6, true).await;
    let another_holder = w.device(7, true).await;
    w.holding(&another_holder).await;
    let unapproved_holder = w.device(8, true).await;
    w.reporting(&unapproved_holder).await;
    w.approve(&unapproved_holder, &phone).await;
    w.approve(&laptop, &not_holding).await;
    let unnamed = w
        .app
        .token_in(w.alice.id, w.app.sign_in.sessions.live(w.alice.id));
    let unknown = Uuid::new_v4();

    let cases = [
        (
            w.app
                .call_in(
                    &unnamed,
                    Method::POST,
                    "/api/history/key-shares",
                    Some(body_for(&w.alice, 1, laptop.id, phone.id, 1)),
                )
                .await,
            StatusCode::FORBIDDEN,
            "device_required",
        ),
        (
            w.held(&unnamed).await,
            StatusCode::FORBIDDEN,
            "device_required",
        ),
        (
            w.share_to(&laptop, &laptop).await,
            StatusCode::BAD_REQUEST,
            "invalid_request",
        ),
        (
            w.share(&laptop, body_for(&w.alice, 1, laptop.id, unknown, 1))
                .await,
            StatusCode::NOT_FOUND,
            "not_found",
        ),
        (
            w.share(&laptop, body_for(&w.alice, 1, laptop.id, phone.id, 2))
                .await,
            StatusCode::CONFLICT,
            "stale_history_key",
        ),
        (
            w.share_to(&not_holding, &phone).await,
            StatusCode::CONFLICT,
            "history_key_not_held",
        ),
        (
            w.share_to(&laptop, &unapproved).await,
            StatusCode::CONFLICT,
            "not_approved",
        ),
        (
            w.share_to(&laptop, &without_hpke).await,
            StatusCode::CONFLICT,
            "no_hpke_key",
        ),
        (
            w.share_to(&another_holder, &phone).await,
            StatusCode::CONFLICT,
            "not_the_approver",
        ),
        (
            w.share_to(&laptop, &holding).await,
            StatusCode::CONFLICT,
            "history_key_held",
        ),
        (
            w.share(&laptop, body_for(&w.alice, 9, laptop.id, phone.id, 1))
                .await,
            StatusCode::BAD_REQUEST,
            "invalid_request",
        ),
    ];

    for (i, ((status, body), expected, code)) in cases.into_iter().enumerate() {
        assert_eq!(
            (status, body["error"].as_str()),
            (expected, Some(code)),
            "{i}: {body}"
        );
    }
    assert_eq!(
        w.share_to(&unapproved_holder, &phone).await,
        (
            StatusCode::CONFLICT,
            refusal(
                "not_approved",
                "This device isn't approved under the current history key"
            )
        )
    );
    assert_eq!(
        w.share_to(&another_holder, &phone).await.1,
        refusal(
            "not_the_approver",
            "Only a device that approved this one shares the history key with it"
        )
    );
    assert_eq!(
        w.share_to(&laptop, &unapproved).await.1,
        refusal(
            "not_approved",
            "The device isn't approved under the current history key"
        )
    );
    assert_eq!(
        w.share(&laptop, body_for(&w.alice, 9, laptop.id, phone.id, 1))
            .await
            .1,
        refusal(
            "invalid_request",
            "signature does not verify over the share"
        )
    );
    assert_eq!(w.held(&phone.token).await.0, StatusCode::NOT_FOUND);
}
