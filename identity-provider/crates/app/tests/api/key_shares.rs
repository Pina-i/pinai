use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};

use crate::approvals::{Device, approve};
use crate::helpers::{TestApp, another_browser, next_event, open_socket, spawn_app};
use crate::start_over::{ask_to_start_over, unused_for_a_week};

/// Sets `generation` from `device`'s session, its approval key `key`'s public half — what a
/// client derives from the HAK by HKDF; any seed stands in for it here.
pub(crate) async fn set_generation(
    app: &TestApp,
    device: &Device,
    generation: i64,
    key: &SigningKey,
) {
    let (set, body) = app
        .send(
            Method::PUT,
            &device.session,
            "/api/history/key",
            json!({
                "generation": generation,
                "salt": B64.encode([1; 16]),
                "check_value": B64.encode([1; 32]),
                "approval_public_key": B64.encode(key.verifying_key().as_bytes()),
            }),
        )
        .await;
    assert_eq!(set, StatusCode::NO_CONTENT, "{body}");
}

/// `device` approved by the words typed on it — `key`, their approval key — and saying it holds
/// `generation`.
pub(crate) async fn holding(app: &TestApp, device: &Device, generation: i64, key: &SigningKey) {
    for (method, path, body) in [
        (
            Method::POST,
            format!("/api/keys/devices/{}/approvals", device.id),
            json!({
                "by": "passphrase",
                "generation": generation,
                "signature": device.approved_by(key),
            }),
        ),
        (
            Method::PUT,
            format!("/api/keys/devices/{}/history-key", device.id),
            json!({ "generation": generation }),
        ),
    ] {
        let (status, answer) = app.send(method, &device.session, &path, body).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{path}: {answer}");
    }
}

/// The share's bytes as identity-provider/specs/e2ee.md § 7.2 writes them: the aad, then the seal.
fn share_bytes(
    actor: &str,
    sender: &str,
    recipient: &str,
    generation: i64,
    enc: &str,
    ciphertext: &str,
) -> String {
    format!(
        "PINAI-HISTORY-SHARE-v1\n{actor}\n{sender}\n{recipient}\n{generation}\n{enc}\n{ciphertext}"
    )
}

/// `sender`'s share of `generation` for `recipient`, signed by its root key. The seal is opaque to
/// the instance: random bytes stand in for HPKE's.
fn share_for(sender: &Device, recipient: &Device, generation: i64) -> Value {
    let enc = B64.encode(rand::random::<[u8; 32]>());
    let ciphertext = B64.encode((0..180).map(|_| rand::random::<u8>()).collect::<Vec<_>>());
    let signed = share_bytes(
        &sender.session.actor_uri,
        &sender.id.to_string(),
        &recipient.id.to_string(),
        generation,
        &enc,
        &ciphertext,
    );
    json!({
        "recipient_device_id": recipient.id,
        "generation": generation,
        "enc": enc,
        "ciphertext": ciphertext,
        "signature": B64.encode(sender.root.sign(signed.as_bytes()).to_bytes()),
    })
}

async fn share(app: &TestApp, from: &Device, body: &Value) -> (StatusCode, Value) {
    app.send(
        Method::POST,
        &from.session,
        "/api/history/key-shares",
        body.clone(),
    )
    .await
}

/// The account's first device, which set generation 1 and holds it, and the generation's
/// approval key.
pub(crate) async fn first_device(app: &TestApp) -> (Device, SigningKey) {
    let alice = app.sign_up("alice").await;
    let laptop = Device::on(app, alice).await;
    let key = SigningKey::from_bytes(&rand::random());
    set_generation(app, &laptop, 1, &key).await;
    holding(app, &laptop, 1, &key).await;
    (laptop, key)
}

/// The laptop holds the passphrase; the two approve each other, as the code handshake ends, and the
/// laptop shares: the phone is told a share waits, reads it, checks its signature from the device
/// list alone, says it holds the generation — and the share is gone.
#[tokio::test]
async fn an_approved_device_receives_the_passphrase_and_its_report_ends_the_share() {
    let app = spawn_app().await;
    let (laptop, _) = first_device(&app).await;
    let phone = Device::on(&app, another_browser(&app, &laptop.session).await).await;
    assert_eq!(
        approve(&app, &laptop, &phone).await,
        (StatusCode::NO_CONTENT, Value::Null)
    );
    approve(&app, &phone, &laptop).await;
    let mut socket = open_socket(&app, &phone.session.token).await.unwrap();
    let body = share_for(&laptop, &phone, 1);

    let shared = share(&app, &laptop, &body).await;
    let ready = next_event(&mut socket, "history_key_ready").await;
    let (read, held) = app.get(&phone.session, "/api/history/key-shares").await;
    let (_, devices) = app.get(&phone.session, "/api/keys/devices").await;
    let (reported, _) = app
        .send(
            Method::PUT,
            &phone.session,
            &format!("/api/keys/devices/{}/history-key", phone.id),
            json!({ "generation": 1 }),
        )
        .await;
    let (after, _) = app.get(&phone.session, "/api/history/key-shares").await;

    assert_eq!(shared, (StatusCode::NO_CONTENT, Value::Null));
    assert_eq!(ready, json!({ "device_id": phone.id }));
    assert_eq!(read, StatusCode::OK, "{held}");
    assert_eq!(held["sender_device_id"], json!(laptop.id));
    assert_eq!(held["generation"], 1);
    assert_eq!(
        (&held["enc"], &held["ciphertext"]),
        (&body["enc"], &body["ciphertext"])
    );
    let sender = devices["devices"]
        .as_array()
        .unwrap()
        .iter()
        .find(|device| device["device_id"] == held["sender_device_id"])
        .expect("the sender is listed");
    let drk: [u8; 32] = B64
        .decode(sender["drk_public_key"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let signature = B64.decode(held["signature"].as_str().unwrap()).unwrap();
    let verified = VerifyingKey::from_bytes(&drk).unwrap().verify_strict(
        share_bytes(
            &phone.session.actor_uri,
            held["sender_device_id"].as_str().unwrap(),
            &phone.id.to_string(),
            1,
            held["enc"].as_str().unwrap(),
            held["ciphertext"].as_str().unwrap(),
        )
        .as_bytes(),
        &Signature::from_slice(&signature).unwrap(),
    );
    assert!(verified.is_ok(), "by the sender's listed root key");
    assert_eq!(reported, StatusCode::NO_CONTENT);
    assert_eq!(after, StatusCode::NOT_FOUND);
    assert_eq!(
        app.count("SELECT COUNT(*) FROM history_key_shares").await,
        0
    );
}

/// After a start over (identity-provider/specs/e2ee.md § 6.11): a new device asks to start over,
/// and once the laptop and the tablet went a week unused sets generation 2 and approves itself
/// with its new words; the old tablet, which holds generation 1, and the new device approve each
/// other; the new device shares the new words with it, and the tablet takes generation 2 on.
#[tokio::test]
async fn after_a_start_over_the_new_device_shares_the_new_words_with_an_old_one() {
    let app = spawn_app().await;
    let (laptop, first_key) = first_device(&app).await;
    let tablet = Device::on(&app, another_browser(&app, &laptop.session).await).await;
    holding(&app, &tablet, 1, &first_key).await;
    let fresh = Device::on(&app, another_browser(&app, &laptop.session).await).await;
    let (asked, request) = ask_to_start_over(&app, &fresh).await;
    assert_eq!(asked, StatusCode::CREATED, "{request}");
    unused_for_a_week(&app, &[&laptop, &tablet]).await;
    let second_key = SigningKey::from_bytes(&rand::random());
    set_generation(&app, &fresh, 2, &second_key).await;
    holding(&app, &fresh, 2, &second_key).await;
    let (_, key) = app.get(&tablet.session, "/api/history/key").await;
    let (from_the_old_words, stale) = share(&app, &laptop, &share_for(&laptop, &tablet, 1)).await;

    approve(&app, &fresh, &tablet).await;
    approve(&app, &tablet, &fresh).await;
    let mut socket = open_socket(&app, &tablet.session.token).await.unwrap();
    let body = share_for(&fresh, &tablet, 2);
    let (shared, _) = share(&app, &fresh, &body).await;
    let ready = next_event(&mut socket, "history_key_ready").await;
    let (_, held) = app.get(&tablet.session, "/api/history/key-shares").await;
    holding(&app, &tablet, 2, &second_key).await;
    let (after, _) = app.get(&tablet.session, "/api/history/key-shares").await;

    assert_eq!(
        (&key["generation"], &key["set_by_device"]),
        (&json!(2), &json!(fresh.id))
    );
    assert_eq!(
        (from_the_old_words, stale["error"].as_str()),
        (StatusCode::CONFLICT, Some("stale_history_key"))
    );
    assert_eq!(shared, StatusCode::NO_CONTENT);
    assert_eq!(ready, json!({ "device_id": tablet.id }));
    assert_eq!(
        (&held["sender_device_id"], &held["generation"]),
        (&json!(fresh.id), &json!(2))
    );
    assert_eq!(
        (&held["enc"], &held["ciphertext"]),
        (&body["enc"], &body["ciphertext"])
    );
    assert_eq!(after, StatusCode::NOT_FOUND);
    assert_eq!(
        app.count("SELECT COUNT(*) FROM history_key_shares").await,
        0
    );
}
