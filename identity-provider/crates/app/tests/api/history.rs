use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use reqwest::Method;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::approvals::Device;
use crate::helpers::{
    Account, TestApp, another_browser, naming_proof, signed_in_long_ago, spawn_app,
};
use crate::key_shares::{holding, set_generation};
use crate::start_over::unused_for_a_week;

/// A history key of generation `generation`, its bytes made of `byte`s, as a client sends it.
fn key(generation: i64, byte: u8) -> Value {
    json!({
        "generation": generation,
        "salt": B64.encode([byte; 16]),
        "check_value": B64.encode([byte; 32]),
        "approval_public_key": B64.encode([byte.wrapping_add(1); 32]),
    })
}

async fn set_key(app: &TestApp, who: &Account, body: Value) -> (reqwest::StatusCode, Value) {
    app.send(Method::PUT, who, "/api/history/key", body).await
}

/// A group of `who`'s with another account, for entries to be archived from.
pub(crate) async fn a_conversation(app: &TestApp, who: &Account) -> String {
    let bob = app.sign_up("bob").await;
    let (opened, body) = app
        .send(
            Method::PATCH,
            &bob,
            "/api/privacy",
            json!({ "contact_policy": "everyone" }),
        )
        .await;
    assert_eq!(opened, 200, "{body}");
    let (created, group) = app
        .send(
            Method::POST,
            who,
            "/api/groups",
            json!({ "member_actor_uris": [bob.actor_uri.as_str()] }),
        )
        .await;
    assert_eq!(created, 201, "{group}");
    group["conversationId"].as_str().unwrap().to_owned()
}

pub(crate) async fn upload(
    app: &TestApp,
    who: &Account,
    generation: i64,
    conversation: &str,
) -> (reqwest::StatusCode, Value) {
    upload_entry(app, who, generation, conversation, Uuid::new_v4(), 1).await
}

/// One entry for message `id`, its ciphertext made of `byte`s.
pub(crate) async fn upload_entry(
    app: &TestApp,
    who: &Account,
    generation: i64,
    conversation: &str,
    id: Uuid,
    byte: u8,
) -> (reqwest::StatusCode, Value) {
    let entry = json!({
        "id": id,
        "conversation_id": conversation,
        "ciphertext": B64.encode([byte; 16]),
        "nonce": B64.encode([byte; 12]),
    });
    app.send(
        Method::POST,
        who,
        "/api/history/messages",
        json!({ "generation": generation, "entries": [entry] }),
    )
    .await
}

pub(crate) async fn archived(app: &TestApp, who: &Account) -> usize {
    let (status, page) = app.get(who, "/api/history/messages").await;
    assert_eq!(status, 200, "{page}");
    page["entries"].as_array().unwrap().len()
}

/// `who`'s session registers a device and names it.
async fn a_device(app: &TestApp, who: &Account) -> Uuid {
    let device = Uuid::new_v4();
    let root = ed25519_dalek::SigningKey::from_bytes(&rand::random());
    let (registered, body) = app
        .send(
            Method::POST,
            who,
            "/api/keys/devices",
            json!({
                "device_id": device,
                "drk_public_key": B64.encode(root.verifying_key().as_bytes()),
            }),
        )
        .await;
    assert_eq!(registered, 201, "{body}");
    let (linked, body) = app
        .send(
            Method::PUT,
            who,
            "/api/sessions/current/device",
            json!({ "device_id": device, "signature": naming_proof(who, device, &root) }),
        )
        .await;
    assert_eq!(linked, 204, "{body}");
    device
}

#[tokio::test]
async fn the_first_key_takes_no_recent_password_and_starting_over_takes_one_and_erases_the_archive()
{
    let app = spawn_app().await;
    let alice = app.sign_up("alice").await;
    let conversation = a_conversation(&app, &alice).await;
    let laptop = Device::on(&app, alice.clone()).await;
    let long_ago = signed_in_long_ago(&app, &alice).await;
    let laptop = Device {
        session: long_ago.clone(),
        ..laptop
    };
    let words = ed25519_dalek::SigningKey::from_bytes(&rand::random());

    let (none_yet, _) = app.get(&long_ago, "/api/history/key").await;
    set_generation(&app, &laptop, 1, &words).await;
    holding(&app, &laptop, 1, &words).await;
    let (uploaded, body) = upload(&app, &long_ago, 1, &conversation).await;
    assert_eq!(uploaded, 200, "{body}");
    let refused = app
        .http
        .put(format!("{}/api/history/key", app.address))
        .bearer_auth(&long_ago.token)
        .json(&key(2, 2))
        .send()
        .await
        .unwrap();
    let kept = archived(&app, &alice).await;
    let recent = another_browser(&app, &alice).await;
    let phone = a_device(&app, &recent).await;
    let (asked, request) = app
        .send(
            Method::POST,
            &recent,
            "/api/history/start-over",
            Value::Null,
        )
        .await;
    assert_eq!(asked, 201, "{request}");
    unused_for_a_week(&app, &[&laptop]).await;
    let (started_over, _) = set_key(&app, &recent, key(2, 2)).await;
    let (stale, refusal) = upload(&app, &long_ago, 1, &conversation).await;
    let (current, held) = app.get(&long_ago, "/api/history/key").await;

    assert_eq!(none_yet, 404);
    assert_eq!(refused.status(), 401);
    assert_eq!(
        refused.headers()["www-authenticate"],
        r#"Bearer error="insufficient_user_authentication", max_age="600""#
    );
    assert_eq!(kept, 1, "a refusal erases nothing");
    assert_eq!(started_over, 204);
    assert_eq!(archived(&app, &alice).await, 0, "the old archive is gone");
    assert_eq!(
        (stale.as_u16(), refusal),
        (
            409,
            json!({
                "error": "stale_history_key",
                "error_description": "Not the account's current history key",
            })
        )
    );
    let mut set_by_the_phone = key(2, 2);
    set_by_the_phone["set_by_device"] = json!(phone);
    assert_eq!((current.as_u16(), held), (200, set_by_the_phone));
    app.stop().await.unwrap();
}

async fn hold(app: &TestApp, session: &Account, device: Uuid) -> (reqwest::StatusCode, Value) {
    app.send(
        Method::PUT,
        session,
        &format!("/api/keys/devices/{device}/history-key"),
        json!({ "generation": 1 }),
    )
    .await
}

#[tokio::test]
async fn a_device_says_it_holds_the_key_from_its_own_session_only_and_the_list_shows_it() {
    let app = spawn_app().await;
    let laptops = app.sign_up("alice").await;
    let phones = another_browser(&app, &laptops).await;
    let (laptop, phone) = (
        a_device(&app, &laptops).await,
        a_device(&app, &phones).await,
    );
    let (set, body) = set_key(&app, &laptops, key(1, 1)).await;
    assert_eq!(set, 204, "{body}");

    let (held, _) = hold(&app, &laptops, laptop).await;
    let (for_another, refusal) = hold(&app, &laptops, phone).await;
    let (listed, devices) = app.get(&phones, "/api/keys/devices").await;

    assert_eq!(held, 204);
    assert_eq!(
        (for_another.as_u16(), refusal),
        (
            403,
            json!({
                "error": "device_mismatch",
                "error_description": "This session signed in another device",
            })
        )
    );
    assert_eq!(listed, 200, "{devices}");
    let generation_of = |device: Uuid| {
        devices["devices"]
            .as_array()
            .unwrap()
            .iter()
            .find(|d| d["device_id"] == json!(device))
            .expect("listed")["history_generation"]
            .clone()
    };
    assert_eq!(generation_of(laptop), json!(1));
    assert_eq!(generation_of(phone), Value::Null);
    app.stop().await.unwrap();
}
