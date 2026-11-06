use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::helpers::{Account, TestApp, another_browser, naming_proof, spawn_app};

/// A device as a client makes it: its root key and HPKE key registered, its session named.
pub(crate) struct Device {
    pub(crate) id: Uuid,
    pub(crate) root: SigningKey,
    pub(crate) session: Account,
}

impl Device {
    pub(crate) async fn on(app: &TestApp, session: Account) -> Self {
        Self::named(app, session, "").await
    }

    /// The device, registering from a client whose `User-Agent` is `user_agent`.
    async fn named(app: &TestApp, session: Account, user_agent: &str) -> Self {
        let (id, root) = (Uuid::new_v4(), SigningKey::from_bytes(&rand::random()));
        let hpke: [u8; 32] = rand::random();
        let hpke_signed = format!(
            "PINAI-DEVICE-HPKE-v1\n{}\n{id}\n{}",
            session.actor_uri,
            B64.encode(hpke)
        );
        let registered = app
            .http
            .post(format!("{}/api/keys/devices", app.address))
            .bearer_auth(&session.token)
            .header(reqwest::header::USER_AGENT, user_agent)
            .json(&json!({
                "device_id": id,
                "drk_public_key": B64.encode(root.verifying_key().as_bytes()),
                "hpke_public_key": B64.encode(hpke),
                "hpke_key_signature": B64.encode(root.sign(hpke_signed.as_bytes()).to_bytes()),
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(registered.status(), StatusCode::CREATED);
        let (named, body) = app
            .send(
                Method::PUT,
                &session,
                "/api/sessions/current/device",
                json!({ "device_id": id, "signature": naming_proof(&session, id, &root) }),
            )
            .await;
        assert_eq!(named, StatusCode::NO_CONTENT, "{body}");
        Self { id, root, session }
    }

    fn drk(&self) -> String {
        B64.encode(self.root.verifying_key().as_bytes())
    }

    /// `signer`'s approval of this device, as identity-provider/specs/e2ee.md § 7.2 writes it.
    pub(crate) fn approved_by(&self, signer: &SigningKey) -> String {
        let signed = approval_bytes(&self.session.actor_uri, self.id, &self.drk());
        B64.encode(signer.sign(signed.as_bytes()).to_bytes())
    }
}

fn approval_bytes(actor: &str, device: Uuid, drk: &str) -> String {
    format!("PINAI-DEVICE-APPROVAL-v1\n{actor}\n{device}\n{drk}")
}

pub(crate) async fn approve(app: &TestApp, by: &Device, device: &Device) -> (StatusCode, Value) {
    app.send(
        Method::POST,
        &by.session,
        &format!("/api/keys/devices/{}/approvals", device.id),
        json!({ "by": "device", "signature": device.approved_by(&by.root) }),
    )
    .await
}

async fn listed(app: &TestApp, who: &Account) -> Vec<Value> {
    let (status, body) = app.get(who, "/api/keys/devices").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["devices"].as_array().unwrap().clone()
}

fn entry<'a>(devices: &'a [Value], device: &Device) -> &'a Value {
    devices
        .iter()
        .find(|d| d["device_id"] == json!(device.id))
        .expect("listed")
}

fn key_of(value: &Value) -> VerifyingKey {
    let bytes: [u8; 32] = B64
        .decode(value.as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    VerifyingKey::from_bytes(&bytes).unwrap()
}

/// The approvals of `device` that verify, by the device list alone — another device's check: the
/// approver's listed root key, the approved device's listed root key, the canonical bytes.
fn verified_approvers(devices: &[Value], actor: &str, device: &Device) -> Vec<Value> {
    let approved = entry(devices, device);
    let drk = approved["drk_public_key"].as_str().unwrap();
    approved["approvals"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|approval| approval["by"] == "device")
        .filter(|approval| {
            let approver = devices
                .iter()
                .find(|d| d["device_id"] == approval["device_id"])
                .expect("the approver is listed");
            let signature = B64.decode(approval["signature"].as_str().unwrap()).unwrap();
            key_of(&approver["drk_public_key"])
                .verify_strict(
                    approval_bytes(actor, device.id, drk).as_bytes(),
                    &Signature::from_slice(&signature).unwrap(),
                )
                .is_ok()
        })
        .map(|approval| approval["device_id"].clone())
        .collect()
}

async fn post(app: &TestApp, from: &Device, request: &str, body: &[u8]) -> (StatusCode, Value) {
    app.send(
        Method::POST,
        &from.session,
        &format!("/api/keys/devices/approval-requests/{request}/messages"),
        json!({ "body": B64.encode(body) }),
    )
    .await
}

/// What `reader` reads of the request after `after`: each message's body.
async fn read(app: &TestApp, reader: &Device, request: &str, after: i64) -> Vec<Vec<u8>> {
    let (status, body) = app
        .get(
            &reader.session,
            &format!("/api/keys/devices/approval-requests/{request}/messages?after={after}"),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| B64.decode(m["body"].as_str().unwrap()).unwrap())
        .collect()
}

async fn open(app: &TestApp, device: &Device) -> String {
    let (opened, request) = app
        .send(
            Method::POST,
            &device.session,
            "/api/keys/devices/approval-requests",
            Value::Null,
        )
        .await;
    assert_eq!(opened, StatusCode::CREATED, "{request}");
    request["id"].as_str().unwrap().to_owned()
}

const ANDROID_CHROME: &str = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 \
     (KHTML, like Gecko) Chrome/130.0 Mobile Safari/537.36";

/// The first device approves itself with the passphrase it made; a new one is approved over the
/// code handshake as two clients run it — the IdP carries each message, opaque —, each device
/// approving the other's root key; the whole is then checked from the device list and the history
/// key alone, with real Ed25519 keys.
#[tokio::test]
async fn two_devices_approve_each_other_over_the_relayed_handshake() {
    let app = spawn_app().await;
    let alice = app.sign_up("alice").await;
    let laptop = Device::on(&app, alice.clone()).await;
    // What a client derives from the HAK by HKDF; any seed stands in for it here.
    let approval_key = SigningKey::from_bytes(&rand::random());
    let (set, body) = app
        .send(
            Method::PUT,
            &laptop.session,
            "/api/history/key",
            json!({
                "generation": 1,
                "salt": B64.encode([1; 16]),
                "check_value": B64.encode([1; 32]),
                "approval_public_key": B64.encode(approval_key.verifying_key().as_bytes()),
            }),
        )
        .await;
    assert_eq!(set, StatusCode::NO_CONTENT, "{body}");
    let (by_words, body) = app
        .send(
            Method::POST,
            &laptop.session,
            &format!("/api/keys/devices/{}/approvals", laptop.id),
            json!({
                "by": "passphrase",
                "generation": 1,
                "signature": laptop.approved_by(&approval_key),
            }),
        )
        .await;
    assert_eq!(by_words, StatusCode::NO_CONTENT, "{body}");
    let phone = Device::named(&app, another_browser(&app, &alice).await, ANDROID_CHROME).await;

    let request = open(&app, &phone).await;
    let (_, waiting) = app
        .get(&laptop.session, "/api/keys/devices/approval-requests")
        .await;
    let (asked, _) = post(&app, &phone, &request, b"spake2: the phone's message").await;
    let at_the_laptop = read(&app, &laptop, &request, 0).await;
    let (answered, _) = post(&app, &laptop, &request, b"spake2: the laptop's message").await;
    let (sealed, _) = post(&app, &laptop, &request, laptop.drk().as_bytes()).await;
    let at_the_phone = read(&app, &phone, &request, 0).await;
    post(&app, &phone, &request, phone.drk().as_bytes()).await;
    let phones_keys = read(&app, &laptop, &request, 1).await;
    let laptop_approves = approve(&app, &laptop, &phone).await;
    let phone_approves = approve(&app, &phone, &laptop).await;
    let (closed, _) = app
        .send(
            Method::DELETE,
            &phone.session,
            &format!("/api/keys/devices/approval-requests/{request}"),
            Value::Null,
        )
        .await;

    assert_eq!(waiting["requests"][0]["id"], json!(request));
    assert_eq!(waiting["requests"][0]["device_id"], json!(phone.id));
    assert_eq!(waiting["requests"][0]["display_name"], "Chrome on Android");
    assert_eq!(
        (asked, answered, sealed),
        (
            StatusCode::CREATED,
            StatusCode::CREATED,
            StatusCode::CREATED
        )
    );
    assert_eq!(at_the_laptop, vec![b"spake2: the phone's message".to_vec()]);
    assert_eq!(
        at_the_phone,
        vec![
            b"spake2: the laptop's message".to_vec(),
            laptop.drk().into_bytes()
        ]
    );
    assert_eq!(phones_keys, vec![phone.drk().into_bytes()]);
    assert_eq!(laptop_approves, (StatusCode::NO_CONTENT, Value::Null));
    assert_eq!(phone_approves, (StatusCode::NO_CONTENT, Value::Null));
    assert_eq!(closed, StatusCode::NO_CONTENT);
    let devices = listed(&app, &alice).await;
    assert_eq!(
        verified_approvers(&devices, &alice.actor_uri, &phone),
        vec![json!(laptop.id)]
    );
    assert_eq!(
        verified_approvers(&devices, &alice.actor_uri, &laptop),
        vec![json!(phone.id)]
    );
    let (_, key) = app.get(&phone.session, "/api/history/key").await;
    let laptops = entry(&devices, &laptop)["approvals"]
        .as_array()
        .unwrap()
        .clone();
    let by_the_words = laptops
        .iter()
        .find(|approval| approval["by"] == "passphrase")
        .expect("the laptop approved itself");
    assert_eq!(by_the_words["generation"], 1);
    let signature = B64
        .decode(by_the_words["signature"].as_str().unwrap())
        .unwrap();
    let verified = key_of(&key["approval_public_key"]).verify_strict(
        approval_bytes(&alice.actor_uri, laptop.id, &laptop.drk()).as_bytes(),
        &Signature::from_slice(&signature).unwrap(),
    );
    assert!(verified.is_ok(), "under the generation's approval key");
    let (_, after) = app
        .get(&laptop.session, "/api/keys/devices/approval-requests")
        .await;
    assert_eq!(after, json!({ "requests": [] }));
}

#[tokio::test]
async fn a_third_device_cannot_join_a_request_another_answers() {
    let app = spawn_app().await;
    let alice = app.sign_up("alice").await;
    let laptop = Device::on(&app, alice.clone()).await;
    let phone = Device::on(&app, another_browser(&app, &alice).await).await;
    let tablet = Device::on(&app, another_browser(&app, &alice).await).await;
    let request = open(&app, &phone).await;
    post(&app, &phone, &request, b"spake2: the phone's message").await;
    post(&app, &laptop, &request, b"spake2: the laptop's message").await;

    let (joined, refusal) = post(&app, &tablet, &request, b"spake2: the tablet's message").await;
    let (tablet_reads, _) = app
        .get(
            &tablet.session,
            &format!("/api/keys/devices/approval-requests/{request}/messages"),
        )
        .await;
    let (closed, _) = app
        .send(
            Method::DELETE,
            &tablet.session,
            &format!("/api/keys/devices/approval-requests/{request}"),
            Value::Null,
        )
        .await;

    assert_eq!(joined, StatusCode::CONFLICT);
    assert_eq!(refusal["error"], "approval_request_taken");
    assert_eq!(
        (tablet_reads, closed),
        (StatusCode::CONFLICT, StatusCode::CONFLICT)
    );
    assert_eq!(
        read(&app, &phone, &request, 0).await,
        vec![b"spake2: the laptop's message".to_vec()]
    );
}
