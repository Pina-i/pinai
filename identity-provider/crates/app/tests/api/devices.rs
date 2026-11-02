use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::helpers::{Account, TestApp, another_browser, spawn_app};

/// A device's root key, and the HPKE key it signs — made as a client makes them.
struct DeviceKeys {
    root: SigningKey,
    hpke: [u8; 32],
}

impl DeviceKeys {
    fn new() -> Self {
        Self {
            root: SigningKey::from_bytes(&rand::random()),
            hpke: rand::random(),
        }
    }

    fn drk(&self) -> String {
        B64.encode(self.root.verifying_key().as_bytes())
    }

    fn hpke_key(&self) -> String {
        B64.encode(self.hpke)
    }

    /// identity-provider/specs/e2ee.md § 7.2, written out as a client would.
    fn hpke_signature(&self, owner: &Account, device: Uuid) -> String {
        let signed = format!(
            "PINAI-DEVICE-HPKE-v1\n{}\n{device}\n{}",
            owner.actor_uri,
            self.hpke_key()
        );
        B64.encode(self.root.sign(signed.as_bytes()).to_bytes())
    }
}

/// `POST /api/keys/devices` with the fields given, and only those.
async fn register(
    app: &TestApp,
    who: &Account,
    device: Uuid,
    fields: &[(&str, String)],
) -> (reqwest::StatusCode, Value) {
    let mut body = Map::new();
    body.insert("device_id".into(), json!(device));
    for (name, value) in fields {
        body.insert((*name).into(), json!(value));
    }
    app.send(
        reqwest::Method::POST,
        who,
        "/api/keys/devices",
        Value::Object(body),
    )
    .await
}

async fn listed(app: &TestApp, who: &Account) -> Vec<Value> {
    let (status, body) = app.get(who, "/api/keys/devices").await;
    assert_eq!(status, 200, "{body}");
    body["devices"]
        .as_array()
        .expect("a list of devices")
        .clone()
}

fn text(value: &Value) -> &str {
    value.as_str().expect("a string")
}

fn bytes(value: &Value) -> Vec<u8> {
    B64.decode(text(value)).unwrap()
}

fn signature(value: &Value) -> Signature {
    Signature::from_slice(&bytes(value)).unwrap()
}

/// What another device of the account checks before encrypting to this one: the instance's key,
/// its attestation of the root key, the root key's signature over the HPKE key — all from the list.
#[tokio::test]
async fn another_device_verifies_the_whole_chain_from_the_device_list_until_it_is_revoked() {
    let app = spawn_app().await;
    let alice = app.sign_up("alice").await;
    let (device, keys) = (Uuid::new_v4(), DeviceKeys::new());

    let (status, registered) = register(
        &app,
        &alice,
        device,
        &[
            ("drk_public_key", keys.drk()),
            ("hpke_public_key", keys.hpke_key()),
            ("hpke_key_signature", keys.hpke_signature(&alice, device)),
        ],
    )
    .await;
    let devices = listed(&app, &alice).await;
    let jwks: Value = app
        .http
        .get(format!("{}/.well-known/jwks.json", app.address))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let (revoked, _) = app
        .send(
            reqwest::Method::POST,
            &alice,
            &format!("/api/keys/devices/{device}/revoke"),
            Value::Null,
        )
        .await;
    let after_the_revoke = listed(&app, &alice).await;

    assert_eq!(status, 201, "{registered}");
    let entry = &devices[0];
    let jwk = jwks["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|jwk| jwk["kid"] == entry["attestation_kid"])
        .expect("the instance publishes the key that attested");
    let instance =
        VerifyingKey::try_from(URL_SAFE_NO_PAD.decode(text(&jwk["x"])).unwrap().as_slice())
            .unwrap();
    let attested = format!(
        "IDP-ATTEST-v1\n{}\n{device}\n{}\n{}\n{}",
        alice.actor_uri,
        text(&entry["drk_public_key"]),
        text(&entry["attestation_expires_at"]),
        text(&entry["attestation_kid"]),
    );
    assert_eq!(
        attested.as_bytes(),
        bytes(&registered["signed_message"]),
        "the list gives back the bytes signed, the expiry to the character"
    );
    assert!(
        instance
            .verify_strict(
                attested.as_bytes(),
                &signature(&entry["attestation_signature"])
            )
            .is_ok()
    );
    let root = VerifyingKey::try_from(bytes(&entry["drk_public_key"]).as_slice()).unwrap();
    let hpke_signed = format!(
        "PINAI-DEVICE-HPKE-v1\n{}\n{device}\n{}",
        alice.actor_uri,
        text(&entry["hpke_public_key"]),
    );
    assert_eq!(entry["hpke_public_key"], json!(keys.hpke_key()));
    assert!(
        root.verify_strict(
            hpke_signed.as_bytes(),
            &signature(&entry["hpke_key_signature"])
        )
        .is_ok()
    );
    assert_eq!(revoked, 204);
    let gone = &after_the_revoke[0];
    assert!(gone["revoked_at"].is_string(), "{gone}");
    assert_eq!(
        (&gone["hpke_public_key"], &gone["hpke_key_signature"]),
        (&Value::Null, &Value::Null),
        "nothing encrypts to a revoked device"
    );
    app.stop().await.unwrap();
}

async fn link(app: &TestApp, who: &Account, device: Uuid) -> (reqwest::StatusCode, Value) {
    app.send(
        reqwest::Method::PUT,
        who,
        "/api/sessions/current/device",
        json!({ "device_id": device }),
    )
    .await
}

#[tokio::test]
async fn a_session_is_limited_to_the_device_it_declared() {
    let app = spawn_app().await;
    let laptop = app.sign_up("alice").await;
    let phone = another_browser(&app, &laptop).await;
    let (laptops, phones) = (Uuid::new_v4(), Uuid::new_v4());
    let (laptop_keys, phone_keys, taking_over) =
        (DeviceKeys::new(), DeviceKeys::new(), DeviceKeys::new());
    for (session, device, keys) in [
        (&laptop, laptops, &laptop_keys),
        (&phone, phones, &phone_keys),
    ] {
        let (registered, body) =
            register(&app, session, device, &[("drk_public_key", keys.drk())]).await;
        assert_eq!(registered, 201, "{body}");
        let (linked, body) = link(&app, session, device).await;
        assert_eq!(linked, 204, "{body}");
    }

    let taken_over = register(
        &app,
        &phone,
        laptops,
        &[
            ("drk_public_key", taking_over.drk()),
            ("hpke_public_key", taking_over.hpke_key()),
            (
                "hpke_key_signature",
                taking_over.hpke_signature(&laptop, laptops),
            ),
        ],
    )
    .await;
    let a_new_one = register(
        &app,
        &phone,
        Uuid::new_v4(),
        &[("drk_public_key", DeviceKeys::new().drk())],
    )
    .await;
    let repointed = link(&app, &phone, laptops).await;
    let (named_again, _) = link(&app, &phone, phones).await;
    let (renewed, _) = register(
        &app,
        &laptop,
        laptops,
        &[("drk_public_key", laptop_keys.drk())],
    )
    .await;
    let devices = listed(&app, &laptop).await;

    let mismatch = json!({
        "error": "device_mismatch",
        "error_description": "This session signed in another device",
    });
    for (status, body) in [taken_over, a_new_one, repointed] {
        assert_eq!((status.as_u16(), body), (403, mismatch.clone()));
    }
    assert_eq!(named_again, 204);
    assert_eq!(
        renewed, 201,
        "the laptop still holds its session and device"
    );
    assert_eq!(devices.len(), 2, "no device was added");
    let held = devices
        .iter()
        .find(|d| d["device_id"] == json!(laptops))
        .expect("listed");
    assert_eq!(
        (&held["drk_public_key"], &held["hpke_public_key"]),
        (&json!(laptop_keys.drk()), &Value::Null)
    );
    app.stop().await.unwrap();
}
