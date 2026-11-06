//! Starting the history over from a device not approved, revoking approved devices, and the other
//! actions only an approved device takes — identity-provider/specs/e2ee.md § 3.12.

use ed25519_dalek::SigningKey;
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::approvals::{Device, approve};
use crate::helpers::{
    Account, TestApp, another_browser, naming_proof, next_event, open_socket, signed_in_long_ago,
    spawn_app,
};
use crate::history::{a_conversation, archived, upload};
use crate::key_shares::{first_device, holding, set_generation};

pub(crate) async fn ask_to_start_over(app: &TestApp, device: &Device) -> (StatusCode, Value) {
    app.send(
        Method::POST,
        &device.session,
        "/api/history/start-over",
        Value::Null,
    )
    .await
}

/// The clock moved on a week and a day without `devices` being used: their sessions' last use and
/// the open start over request moved back as much.
pub(crate) async fn unused_for_a_week(app: &TestApp, devices: &[&Device]) {
    let ids: Vec<String> = devices.iter().map(|d| format!("'{}'", d.id)).collect();
    app.execute(&format!(
        "UPDATE sessions SET last_used_at = last_used_at - interval '8 days' \
         WHERE device_id IN ({})",
        ids.join(", ")
    ))
    .await;
    app.execute(
        "UPDATE start_over_requests SET created_at = created_at - interval '8 days' \
         WHERE ended_at IS NULL",
    )
    .await;
}

async fn put_key(app: &TestApp, who: &Account, generation: i64) -> (StatusCode, Value) {
    let key = SigningKey::from_bytes(&rand::random());
    app.send(
        Method::PUT,
        who,
        "/api/history/key",
        json!({
            "generation": generation,
            "salt": base64(&[2; 16]),
            "check_value": base64(&[2; 32]),
            "approval_public_key": base64(key.verifying_key().as_bytes()),
        }),
    )
    .await
}

fn base64(bytes: &[u8]) -> String {
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes)
}

async fn revoke(app: &TestApp, by: &Account, device: &Device) -> (StatusCode, Value) {
    app.send(
        Method::POST,
        by,
        &format!("/api/keys/devices/{}/revoke", device.id),
        Value::Null,
    )
    .await
}

fn at(value: &Value) -> OffsetDateTime {
    OffsetDateTime::parse(value.as_str().expect("a time"), &Rfc3339).unwrap()
}

/// Someone holding only the password signs in on a device of their own and asks to start over:
/// the laptop, approved and in use, is told; the request isn't ready while it is used, the thief
/// can't revoke it, and the laptop cancels it at once — no password asked.
#[tokio::test]
async fn a_thiefs_start_over_waits_while_an_approved_device_is_used_and_is_cancelled_from_it() {
    let app = spawn_app().await;
    let (laptop, _) = first_device(&app).await;
    let mut laptops_socket = open_socket(&app, &laptop.session.token).await.unwrap();
    let thief = Device::on(&app, another_browser(&app, &laptop.session).await).await;
    let mut thiefs_socket = open_socket(&app, &thief.session.token).await.unwrap();

    let (asked, request) = ask_to_start_over(&app, &thief).await;
    let told = next_event(&mut laptops_socket, "start_over_requested").await;
    let not_ready = put_key(&app, &thief.session, 2).await;
    let revoking = revoke(&app, &thief.session, &laptop).await;
    let (read, pending) = app.get(&laptop.session, "/api/history/start-over").await;
    let long_ago = signed_in_long_ago(&app, &laptop.session).await;
    let (cancelled, _) = app
        .send(
            Method::DELETE,
            &long_ago,
            &format!(
                "/api/history/start-over/{}",
                request["id"].as_str().unwrap()
            ),
            Value::Null,
        )
        .await;
    let cancel = next_event(&mut thiefs_socket, "start_over_cancelled").await;
    let after = put_key(&app, &thief.session, 2).await;
    let (by_the_thief, ended) = app.get(&thief.session, "/api/history/start-over").await;
    let (none_open, _) = app.get(&long_ago, "/api/history/start-over").await;
    let (_, key) = app.get(&laptop.session, "/api/history/key").await;

    assert_eq!(asked, StatusCode::CREATED, "{request}");
    assert_eq!(
        at(&request["ready_at"]),
        at(&request["created_at"]) + time::Duration::days(7),
        "the laptop was used as it opened"
    );
    assert_eq!(
        told,
        json!({
            "request_id": request["id"],
            "device_id": thief.id,
            "display_name": "Web client",
            "ready_at": request["ready_at"],
        })
    );
    assert_eq!(
        not_ready,
        (
            StatusCode::FORBIDDEN,
            json!({
                "error": "start_over_not_ready",
                "error_description": "No approved device may be used for a week first",
                "ready_at": request["ready_at"],
            })
        )
    );
    assert_eq!(
        (revoking.0, revoking.1["error"].as_str()),
        (StatusCode::FORBIDDEN, Some("approval_required"))
    );
    assert_eq!(read, StatusCode::OK);
    assert_eq!(
        (&pending["id"], &pending["device_id"]),
        (&request["id"], &json!(thief.id))
    );
    assert_eq!(cancelled, StatusCode::NO_CONTENT);
    assert_eq!(
        cancel,
        json!({ "request_id": request["id"], "reason": "cancelled" })
    );
    assert_eq!(
        (after.0, after.1["error"].as_str()),
        (StatusCode::FORBIDDEN, Some("start_over_required"))
    );
    assert_eq!(
        by_the_thief,
        StatusCode::OK,
        "the thief's device reads how it ended"
    );
    assert_eq!(
        (&ended["id"], &ended["ended"]["reason"]),
        (&request["id"], &json!("cancelled"))
    );
    assert_eq!(none_open, StatusCode::NOT_FOUND);
    assert_eq!(
        (&key["generation"], &key["set_by_device"]),
        (&json!(1), &json!(laptop.id))
    );
    app.stop().await.unwrap();
}

/// The user lost the laptop and the phone, and the words: a new device asks to start over, and
/// once neither was used for a week, sets generation 2 — then, approved by its new words, revokes
/// the two, approved under generation 1 only.
#[tokio::test]
async fn a_lost_everything_start_over_matures_after_a_week_unused_and_the_old_devices_go_after() {
    let app = spawn_app().await;
    let (laptop, _) = first_device(&app).await;
    let phone = Device::on(&app, another_browser(&app, &laptop.session).await).await;
    approve(&app, &laptop, &phone).await;
    approve(&app, &phone, &laptop).await;
    let fresh = Device::on(&app, another_browser(&app, &laptop.session).await).await;

    let (asked, request) = ask_to_start_over(&app, &fresh).await;
    let too_soon = put_key(&app, &fresh.session, 2).await;
    unused_for_a_week(&app, &[&laptop, &phone]).await;
    let (_, matured) = app.get(&fresh.session, "/api/history/start-over").await;
    let new_words = SigningKey::from_bytes(&rand::random());
    set_generation(&app, &fresh, 2, &new_words).await;
    let (_, used) = app.get(&fresh.session, "/api/history/start-over").await;
    holding(&app, &fresh, 2, &new_words).await;
    let laptops = revoke(&app, &fresh.session, &laptop).await;
    let phones = revoke(&app, &fresh.session, &phone).await;
    let (_, key) = app.get(&fresh.session, "/api/history/key").await;

    assert_eq!(asked, StatusCode::CREATED, "{request}");
    assert_eq!(
        (too_soon.0, too_soon.1["error"].as_str()),
        (StatusCode::FORBIDDEN, Some("start_over_not_ready"))
    );
    assert!(
        at(&matured["ready_at"]) < OffsetDateTime::now_utc(),
        "{matured}"
    );
    assert_eq!(used["ended"]["reason"], "used");
    assert_eq!(
        app.count("SELECT COUNT(*) FROM start_over_requests WHERE ended_reason = 'used'")
            .await,
        1
    );
    assert_eq!(
        (&key["generation"], &key["set_by_device"]),
        (&json!(2), &json!(fresh.id))
    );
    assert_eq!(laptops, (StatusCode::NO_CONTENT, Value::Null));
    assert_eq!(phones, (StatusCode::NO_CONTENT, Value::Null));
    app.stop().await.unwrap();
}

/// A device nobody approved can't sign the laptop out, approved as it is; it can sign itself out.
#[tokio::test]
async fn an_unapproved_device_is_refused_an_approved_ones_revoke_and_may_revoke_itself() {
    let app = spawn_app().await;
    let (laptop, _) = first_device(&app).await;
    let other = Device::on(&app, another_browser(&app, &laptop.session).await).await;

    let refused = revoke(&app, &other.session, &laptop).await;
    let (still, _) = app.get(&laptop.session, "/userinfo").await;
    let itself = revoke(&app, &other.session, &other).await;
    let (signed_out, _) = app.get(&other.session, "/userinfo").await;

    assert_eq!(
        refused,
        (
            StatusCode::FORBIDDEN,
            json!({
                "error": "approval_required",
                "error_description": "This takes a device approved under the current history key",
            })
        )
    );
    assert_eq!(still, StatusCode::OK, "nothing was signed out");
    assert_eq!(itself, (StatusCode::NO_CONTENT, Value::Null));
    assert_eq!(signed_out, StatusCode::UNAUTHORIZED);
    app.stop().await.unwrap();
}

/// Replacing the words from the laptop, approved, needs no request and no wait; another device's
/// open request ends with the generation it would have replaced, and that device is told.
#[tokio::test]
async fn a_replacement_by_an_approved_device_stays_immediate() {
    let app = spawn_app().await;
    let (laptop, _) = first_device(&app).await;
    let fresh = Device::on(&app, another_browser(&app, &laptop.session).await).await;
    let (_, request) = ask_to_start_over(&app, &fresh).await;
    let mut freshs_socket = open_socket(&app, &fresh.session.token).await.unwrap();

    let replaced = put_key(&app, &laptop.session, 2).await;
    let ended = next_event(&mut freshs_socket, "start_over_cancelled").await;
    let (_, key) = app.get(&laptop.session, "/api/history/key").await;
    let (_, read) = app.get(&fresh.session, "/api/history/start-over").await;

    assert_eq!(replaced, (StatusCode::NO_CONTENT, Value::Null));
    assert_eq!(
        ended,
        json!({ "request_id": request["id"], "reason": "superseded" })
    );
    assert_eq!(
        (&key["generation"], &key["set_by_device"]),
        (&json!(2), &json!(laptop.id))
    );
    assert_eq!(read["ended"]["reason"], "superseded");
    app.stop().await.unwrap();
}

/// Someone with only the password signs in and names the laptop's device on their session, to
/// speak as it: without the laptop's root key, the naming is refused, and the laptop stays signed
/// in with its device.
#[tokio::test]
async fn a_password_only_session_naming_the_laptop_is_refused() {
    let app = spawn_app().await;
    let (laptop, _) = first_device(&app).await;
    let thief = another_browser(&app, &laptop.session).await;
    let stranger = SigningKey::from_bytes(&rand::random());

    let mut refusals = Vec::new();
    for signature in [
        Value::Null,
        json!(naming_proof(&thief, laptop.id, &stranger)),
        json!(naming_proof(&laptop.session, laptop.id, &laptop.root)),
    ] {
        refusals.push(
            app.send(
                Method::PUT,
                &thief,
                "/api/sessions/current/device",
                json!({ "device_id": laptop.id, "signature": signature }),
            )
            .await,
        );
    }
    let (still, _) = app.get(&laptop.session, "/userinfo").await;
    let (_, devices) = app.get(&laptop.session, "/api/keys/devices").await;

    for refused in refusals {
        assert_eq!(
            (refused.0, refused.1["error"].as_str()),
            (StatusCode::FORBIDDEN, Some("device_proof_invalid"))
        );
    }
    assert_eq!(still, StatusCode::OK, "the laptop stays signed in");
    let listed = devices["devices"]
        .as_array()
        .unwrap()
        .iter()
        .find(|device| device["device_id"] == json!(laptop.id))
        .unwrap()
        .clone();
    assert_eq!(listed["signed_in"], true);
    app.stop().await.unwrap();
}

/// Someone with only the password registers another root key under the laptop's id, which would
/// drop its approvals: from a session that named no device, refused, and the laptop stays
/// approved.
#[tokio::test]
async fn a_password_only_session_rotating_the_laptops_root_key_is_refused() {
    let app = spawn_app().await;
    let (laptop, _) = first_device(&app).await;
    let thief = another_browser(&app, &laptop.session).await;
    let stranger = SigningKey::from_bytes(&rand::random());

    let rotated = app
        .send(
            Method::POST,
            &thief,
            "/api/keys/devices",
            json!({
                "device_id": laptop.id,
                "drk_public_key": base64(stranger.verifying_key().as_bytes()),
            }),
        )
        .await;
    let (_, devices) = app.get(&laptop.session, "/api/keys/devices").await;

    assert_eq!(
        (rotated.0, rotated.1["error"].as_str()),
        (StatusCode::FORBIDDEN, Some("device_required"))
    );
    let listed = devices["devices"]
        .as_array()
        .unwrap()
        .iter()
        .find(|device| device["device_id"] == json!(laptop.id))
        .unwrap()
        .clone();
    assert_eq!(
        listed["drk_public_key"],
        json!(base64(laptop.root.verifying_key().as_bytes()))
    );
    assert_eq!(
        listed["approvals"].as_array().map(Vec::len),
        Some(1),
        "its approval by its words stays"
    );
    app.stop().await.unwrap();
}

/// Turning the second factor on takes an approved device once the account has a history key: a
/// password thief would otherwise lock the user's devices out of signing in, and a week later
/// start the history over.
#[tokio::test]
async fn only_an_approved_device_turns_the_second_factor_on() {
    let app = spawn_app().await;
    let (laptop, _) = first_device(&app).await;
    let thief = Device::on(&app, another_browser(&app, &laptop.session).await).await;

    let by_the_thief = app
        .send(
            Method::POST,
            &thief.session,
            "/api/totp/enroll",
            Value::Null,
        )
        .await;
    let by_the_laptop = app
        .send(
            Method::POST,
            &laptop.session,
            "/api/totp/enroll",
            Value::Null,
        )
        .await;

    assert_eq!(
        by_the_thief,
        (
            StatusCode::FORBIDDEN,
            json!({
                "error": "approval_required",
                "error_description": "This takes a device approved under the current history key",
            })
        )
    );
    assert_eq!(by_the_laptop.0, StatusCode::OK, "{}", by_the_laptop.1);
    assert!(by_the_laptop.1["secret_base32"].is_string());
    app.stop().await.unwrap();
}

async fn clear(app: &TestApp, by: &Account) -> (StatusCode, Value) {
    app.send(Method::DELETE, by, "/api/history/messages", Value::Null)
        .await
}

async fn sign_out_others(app: &TestApp, by: &Account) -> (StatusCode, Value) {
    app.send(
        Method::DELETE,
        by,
        "/api/sessions?keep=current",
        Value::Null,
    )
    .await
}

fn approval_required() -> (StatusCode, Value) {
    (
        StatusCode::FORBIDDEN,
        json!({
            "error": "approval_required",
            "error_description": "This takes a device approved under the current history key",
        }),
    )
}

/// Someone with only the password, its recent sign-in and all, can neither erase the history
/// backup a device added later restores from, nor sign the user's devices out.
#[tokio::test]
async fn a_password_only_session_neither_clears_the_history_backup_nor_signs_the_laptop_out() {
    let app = spawn_app().await;
    let (laptop, _) = first_device(&app).await;
    let conversation = a_conversation(&app, &laptop.session).await;
    let (uploaded, body) = upload(&app, &laptop.session, 1, &conversation).await;
    assert_eq!(uploaded, StatusCode::OK, "{body}");
    let thief = another_browser(&app, &laptop.session).await;

    let cleared = clear(&app, &thief).await;
    let kept = archived(&app, &laptop.session).await;
    let signed_out = sign_out_others(&app, &thief).await;
    let (still, _) = app.get(&laptop.session, "/userinfo").await;

    assert_eq!(cleared, approval_required());
    assert_eq!(kept, 1, "the archive is intact");
    assert_eq!(signed_out, approval_required());
    assert_eq!(still, StatusCode::OK, "the laptop stays signed in");
    app.stop().await.unwrap();
}

/// The laptop, approved, clears the history backup and signs the other devices out.
#[tokio::test]
async fn the_approved_laptop_clears_the_history_backup_and_signs_the_others_out() {
    let app = spawn_app().await;
    let (laptop, _) = first_device(&app).await;
    let conversation = a_conversation(&app, &laptop.session).await;
    upload(&app, &laptop.session, 1, &conversation).await;
    let elsewhere = another_browser(&app, &laptop.session).await;

    let cleared = clear(&app, &laptop.session).await;
    let left = archived(&app, &laptop.session).await;
    let signed_out = sign_out_others(&app, &laptop.session).await;
    let (gone, _) = app.get(&elsewhere, "/userinfo").await;
    let (kept, _) = app.get(&laptop.session, "/userinfo").await;

    assert_eq!(cleared, (StatusCode::OK, json!({ "deleted": 1 })));
    assert_eq!(left, 0);
    assert_eq!(signed_out, (StatusCode::NO_CONTENT, Value::Null));
    assert_eq!(
        (gone, kept),
        (StatusCode::UNAUTHORIZED, StatusCode::OK),
        "the other browser signed out, the laptop not"
    );
    app.stop().await.unwrap();
}
