use std::time::Duration;

use tokio::io::AsyncReadExt;

use base64::Engine as _;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::helpers::{
    Account, CHALLENGE, OtherWebApp, PASSWORD, TestApp, VERIFIER, another_browser, authorize,
    closed_as_ended, location, open_socket, query_of, signed_in_again, spawn_app,
};

#[tokio::test]
async fn signing_out_closes_the_sessions_sockets_and_its_tokens_stop_working() {
    let app = spawn_app().await;
    let alice = app.sign_up("alice").await;
    let mut socket = open_socket(&app, &alice.token).await.unwrap();

    let signed_out = app
        .http
        .get(format!("{}/logout", app.address))
        .header("cookie", &alice.cookie)
        .send()
        .await
        .unwrap();
    let mut frames = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), socket.read_to_end(&mut frames))
        .await
        .expect("the socket was closed")
        .unwrap();
    let (status, userinfo) = app.get(&alice, "/userinfo").await;
    let reopened = open_socket(&app, &alice.token).await;

    assert_eq!(signed_out.status(), 303);
    // A close frame, `0x88`, whose code is 1008: the session it was opened under has ended.
    let close = frames
        .windows(4)
        .position(|w| w[0] == 0x88 && u16::from_be_bytes([w[2], w[3]]) == 1008);
    assert!(close.is_some(), "{frames:02x?}");
    assert_eq!(status, 401);
    assert_eq!(userinfo["error_description"], "The session has ended");
    assert_eq!(reopened.err().as_deref(), Some("HTTP/1.1 401 Unauthorized"));
    app.stop().await.unwrap();
}

#[tokio::test]
async fn a_live_session_signs_its_app_in_again_and_slides() {
    let app = spawn_app().await;
    let alice = app.sign_up("alice").await;
    let mut pairs = vec![("response_type", "code".to_owned())];
    pairs.extend(app.the_request());

    let again = app
        .http
        .get(format!("{}/authorize", app.address))
        .query(&pairs)
        .header("cookie", &alice.cookie)
        .send()
        .await
        .unwrap();

    assert_eq!(again.status(), 303);
    let location = again.headers()["location"].to_str().unwrap();
    assert!(location.starts_with(&app.redirect_uri), "{location}");
    let cookie = again.headers()["set-cookie"].to_str().unwrap();
    assert!(
        cookie.starts_with(&alice.cookie),
        "the same session: {cookie}"
    );
    assert!(cookie.contains("Max-Age=7776000"), "{cookie}");
    app.stop().await.unwrap();
}

#[tokio::test]
async fn refresh_tokens_renew_the_access_until_a_copy_comes_back_and_ends_the_session() {
    let app = spawn_app().await;
    let alice = app.sign_up("alice").await;

    let (first, once) = app.refresh(&alice.refresh_token).await;
    let (second, twice) = app.refresh(once["refresh_token"].as_str().unwrap()).await;
    let renewed = Account {
        token: twice["access_token"].as_str().unwrap().to_owned(),
        ..alice.clone()
    };
    let (works, _) = app.get(&renewed, "/userinfo").await;
    let mut socket = open_socket(&app, &renewed.token).await.unwrap();
    let (copied, refused) = app.refresh(&alice.refresh_token).await;
    let closed = closed_as_ended(&mut socket).await;
    let (after, _) = app.get(&renewed, "/userinfo").await;
    let (head, _) = app.refresh(twice["refresh_token"].as_str().unwrap()).await;

    assert_eq!(
        [first, second, works].map(|status| status.as_u16()),
        [200; 3]
    );
    assert!(twice.get("id_token").is_none(), "{twice}");
    assert_ne!(once["refresh_token"], twice["refresh_token"]);
    assert_eq!(copied, 400);
    assert_eq!(refused["error"], "invalid_grant");
    assert!(closed, "its socket closed with 1008");
    assert_eq!(after, 401);
    assert_eq!(head, 400, "the latest token goes with its session");
    assert_eq!(
        app.count("SELECT count(*) FROM sessions WHERE revoked_reason = 'reuse'")
            .await,
        1
    );
    app.stop().await.unwrap();
}

#[tokio::test]
async fn revoking_a_device_from_another_signs_it_out_and_closes_its_socket() {
    let app = spawn_app().await;
    let laptop = app.sign_up("alice").await;
    let device = uuid::Uuid::new_v4();
    let (registered, _) = app
        .send(
            reqwest::Method::POST,
            &laptop,
            "/api/keys/devices",
            serde_json::json!({
                "device_id": device,
                "drk_public_key": "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=",
            }),
        )
        .await;
    let (linked, _) = app
        .send(
            reqwest::Method::PUT,
            &laptop,
            "/api/sessions/current/device",
            serde_json::json!({ "device_id": device }),
        )
        .await;
    let mut socket = open_socket(&app, &laptop.token).await.unwrap();
    let phone = another_browser(&app, &laptop).await;
    let (_, listed) = app.get(&phone, "/api/keys/devices").await;

    let (revoked, _) = app
        .send(
            reqwest::Method::POST,
            &phone,
            &format!("/api/keys/devices/{device}/revoke"),
            serde_json::Value::Null,
        )
        .await;
    let closed = closed_as_ended(&mut socket).await;
    let (refused, _) = app.get(&laptop, "/userinfo").await;
    let (renewal, _) = app.refresh(&laptop.refresh_token).await;
    let (still, _) = app.get(&phone, "/userinfo").await;

    assert_eq!(
        [registered, linked].map(|status| status.as_u16()),
        [201, 204]
    );
    assert_eq!(listed["devices"][0]["signed_in"], true);
    assert_eq!(revoked, 204);
    assert!(closed, "its socket closed with 1008");
    assert_eq!(
        [refused, renewal].map(|status| status.as_u16()),
        [401, 400],
        "its tokens with it"
    );
    assert_eq!(still, 200, "the device that revoked it stays");
    assert_eq!(
        app.count("SELECT count(*) FROM sessions WHERE revoked_reason = 'device_revoked'")
            .await,
        2,
        "the web app's session and the browser session above it"
    );
    app.stop().await.unwrap();
}

#[tokio::test]
async fn signing_out_of_every_other_device_keeps_this_one() {
    let app = spawn_app().await;
    let here = app.sign_up("alice").await;
    let there = another_browser(&app, &here).await;
    let mut socket = open_socket(&app, &there.token).await.unwrap();

    let signed_out = app
        .http
        .delete(format!("{}/api/sessions?keep=current", app.address))
        .bearer_auth(&here.token)
        .send()
        .await
        .unwrap()
        .status();
    let closed = closed_as_ended(&mut socket).await;
    let (gone, _) = app.get(&there, "/userinfo").await;
    let (kept, _) = app.get(&here, "/userinfo").await;

    assert_eq!(signed_out, 204);
    assert!(closed, "the other's socket closed with 1008");
    assert_eq!([gone, kept].map(|status| status.as_u16()), [401, 200]);
    app.stop().await.unwrap();
}

#[tokio::test]
async fn the_desktop_signs_out_by_revoking_its_token_and_signs_in_again_with_the_password() {
    let app = spawn_app().await;
    let alice = app.sign_up("alice").await;
    let desktop = format!("{}/clients/desktop.json", app.address);
    let request = |prompt: Option<&'static str>| {
        let mut pairs = vec![
            ("response_type", "code".to_owned()),
            ("client_id", desktop.clone()),
            ("redirect_uri", "io.github.pina-i:/callback".to_owned()),
            ("scope", "openid profile email offline_access".to_owned()),
            ("state", "desktop-state".to_owned()),
            ("code_challenge", CHALLENGE.to_owned()),
            ("code_challenge_method", "S256".to_owned()),
        ];
        if let Some(prompt) = prompt {
            pairs.push(("prompt", prompt.to_owned()));
        }
        pairs
    };
    let signed_in = app
        .http
        .post(format!("{}/login", app.address))
        .form(
            &[
                request(None),
                vec![
                    ("email", alice.email.clone()),
                    ("password", PASSWORD.to_owned()),
                ],
            ]
            .concat(),
        )
        .header("cookie", &alice.cookie)
        .send()
        .await
        .unwrap();
    let tokens: serde_json::Value = app
        .http
        .post(format!("{}/token", app.address))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", query_of(&location(&signed_in))["code"].as_str()),
            ("redirect_uri", "io.github.pina-i:/callback"),
            ("client_id", &desktop),
            ("code_verifier", VERIFIER),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let on_desktop = Account {
        token: tokens["access_token"].as_str().unwrap().to_owned(),
        ..alice.clone()
    };

    let revoked = app
        .http
        .post(format!("{}/revoke", app.address))
        .form(&[
            ("client_id", desktop.as_str()),
            ("token", tokens["refresh_token"].as_str().unwrap()),
        ])
        .send()
        .await
        .unwrap()
        .status();
    let (desktop_api, _) = app.get(&on_desktop, "/userinfo").await;
    let (browser_api, _) = app.get(&alice, "/userinfo").await;
    let again = |prompt| {
        app.http
            .get(format!("{}/authorize", app.address))
            .query(&request(prompt))
            .header("cookie", &alice.cookie)
            .send()
    };
    let silent = again(None).await.unwrap();
    let asked = again(Some("login")).await.unwrap();

    assert_eq!(revoked, 200);
    assert_eq!(
        [desktop_api, browser_api].map(|status| status.as_u16()),
        [401, 200],
        "the app's session ended, the browser's stays"
    );
    assert!(
        location(&silent).starts_with("io.github.pina-i:/callback?"),
        "{}",
        location(&silent)
    );
    assert!(
        location(&asked).starts_with("/login?"),
        "prompt=login asks the password: {}",
        location(&asked)
    );
    app.stop().await.unwrap();
}

/// `who`'s web app registers `device` under a root key of `seed` bytes, then names it on its
/// session: both statuses, and the registration's answer.
async fn sign_in_device(
    app: &TestApp,
    who: &Account,
    device: Uuid,
    seed: u8,
) -> (reqwest::StatusCode, reqwest::StatusCode, Value) {
    let (registered, answer) = app
        .send(
            reqwest::Method::POST,
            who,
            "/api/keys/devices",
            json!({
                "device_id": device,
                "drk_public_key": base64::engine::general_purpose::STANDARD.encode([seed; 32]),
            }),
        )
        .await;
    let (linked, _) = name_device(app, who, device).await;
    (registered, linked, answer)
}

async fn name_device(app: &TestApp, who: &Account, device: Uuid) -> (reqwest::StatusCode, Value) {
    app.send(
        reqwest::Method::PUT,
        who,
        "/api/sessions/current/device",
        json!({ "device_id": device }),
    )
    .await
}

/// The desktop app signing in with the password through the browser holding `who`'s cookie, as
/// its window does, staying signed in: its tokens.
async fn desktop_signs_in(app: &TestApp, who: &Account) -> (Account, String) {
    let desktop = format!("{}/clients/desktop.json", app.address);
    let signed_in = app
        .http
        .post(format!("{}/login", app.address))
        .form(&[
            ("email", who.email.as_str()),
            ("password", PASSWORD),
            ("client_id", &desktop),
            ("redirect_uri", "io.github.pina-i:/callback"),
            ("scope", "openid profile email offline_access"),
            ("state", "desktop-state"),
            ("code_challenge", CHALLENGE),
            ("code_challenge_method", "S256"),
        ])
        .header("cookie", &who.cookie)
        .send()
        .await
        .unwrap();
    let tokens: Value = app
        .http
        .post(format!("{}/token", app.address))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", query_of(&location(&signed_in))["code"].as_str()),
            ("redirect_uri", "io.github.pina-i:/callback"),
            ("client_id", &desktop),
            ("code_verifier", VERIFIER),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let on_desktop = Account {
        token: tokens["access_token"].as_str().unwrap().to_owned(),
        refresh_token: tokens["refresh_token"].as_str().unwrap().to_owned(),
        ..who.clone()
    };
    (on_desktop, desktop)
}

#[tokio::test]
async fn two_web_apps_in_one_browser_each_sign_in_a_device_of_their_own() {
    let app = spawn_app().await;
    // The official web app's sign-up opened the browser session the cookie names.
    let official = app.sign_up("alice").await;
    let instances = OtherWebApp::start().await;
    let (officials_device, instances_device) = (Uuid::new_v4(), Uuid::new_v4());
    let official_signs_in = sign_in_device(&app, &official, officials_device, 7).await;

    let theirs = instances.sign_in(&app, &official).await;
    let they_sign_in = sign_in_device(&app, &theirs, instances_device, 8).await;
    let reloaded = signed_in_again(&app, &official).await;
    let (named_again, _) = name_device(&app, &reloaded, officials_device).await;
    let (repointed, refusal) = name_device(&app, &reloaded, instances_device).await;
    let they_reload = instances.sign_in_again(&app, &official).await;
    let (they_name_again, _) = name_device(&app, &they_reload, instances_device).await;
    let (_, listed) = app.get(&they_reload, "/api/keys/devices").await;

    assert_eq!(
        (official_signs_in.0.as_u16(), official_signs_in.1.as_u16()),
        (201, 204)
    );
    assert_eq!(
        (they_sign_in.0.as_u16(), they_sign_in.1.as_u16()),
        (201, 204),
        "no device_mismatch: {}",
        they_sign_in.2
    );
    assert_eq!(
        [named_again, they_name_again].map(|status| status.as_u16()),
        [204, 204],
        "a reload's sign-in finds its session, and the device it named"
    );
    assert_eq!(
        (repointed.as_u16(), refusal["error"].as_str()),
        (403, Some("device_mismatch")),
        "each session still names one device"
    );
    let devices = listed["devices"].as_array().unwrap();
    assert_eq!(devices.len(), 2);
    assert!(
        devices.iter().all(|device| device["signed_in"] == true),
        "{listed}"
    );
    assert_eq!(
        app.count(
            "SELECT count(*) FROM sessions WHERE kind = 'web' AND revoked_at IS NULL \
             AND browser_session_id = (SELECT id FROM sessions WHERE kind = 'browser')"
        )
        .await,
        2,
        "one session an app, under the one browser session"
    );
    app.stop().await.unwrap();
}

#[tokio::test]
async fn signing_out_of_the_browser_signs_out_its_web_apps_and_never_the_desktop() {
    let app = spawn_app().await;
    let official = app.sign_up("alice").await;
    let instances = OtherWebApp::start().await;
    let theirs = instances.sign_in(&app, &official).await;
    let (on_desktop, desktop) = desktop_signs_in(&app, &official).await;
    let mut sockets = Vec::new();
    for who in [&official, &theirs] {
        sockets.push(open_socket(&app, &who.token).await.unwrap());
    }

    let signed_out = app
        .http
        .get(format!("{}/logout", app.address))
        .header("cookie", &official.cookie)
        .send()
        .await
        .unwrap();
    let mut closed = Vec::new();
    for socket in &mut sockets {
        closed.push(closed_as_ended(socket).await);
    }
    let (officials_api, _) = app.get(&official, "/userinfo").await;
    let (their_api, _) = app.get(&theirs, "/userinfo").await;
    let (officials_renewal, _) = app.refresh(&official.refresh_token).await;
    let their_renewal = instances.refresh(&app, &theirs.refresh_token).await;
    let (desktop_api, _) = app.get(&on_desktop, "/userinfo").await;
    let desktop_renewal = app
        .http
        .post(format!("{}/token", app.address))
        .form(&[
            ("grant_type", "refresh_token"),
            ("client_id", desktop.as_str()),
            ("refresh_token", on_desktop.refresh_token.as_str()),
        ])
        .send()
        .await
        .unwrap()
        .status();
    let back = authorize(&app, &instances.request(), &official.cookie).await;

    assert_eq!(signed_out.status(), 303);
    assert_eq!(closed, [true, true], "both apps' sockets closed with 1008");
    assert_eq!(
        [officials_api, their_api, officials_renewal, their_renewal].map(|s| s.as_u16()),
        [401, 401, 400, 400],
        "both web apps are signed out"
    );
    assert_eq!(
        [desktop_api, desktop_renewal].map(|s| s.as_u16()),
        [200, 200],
        "the desktop's session is its own"
    );
    assert!(
        location(&back).starts_with("/login?"),
        "the password is asked again: {}",
        location(&back)
    );
    assert_eq!(
        app.count("SELECT count(*) FROM sessions WHERE revoked_reason = 'sign_out'")
            .await,
        3,
        "the browser session and its two web apps"
    );
    app.stop().await.unwrap();
}

#[tokio::test]
async fn revoking_a_web_apps_device_signs_out_its_browser_and_that_browsers_other_web_app() {
    let app = spawn_app().await;
    let laptop = app.sign_up("alice").await;
    let instances = OtherWebApp::start().await;
    let beside = instances.sign_in(&app, &laptop).await;
    let (laptops_device, besides_device) = (Uuid::new_v4(), Uuid::new_v4());
    sign_in_device(&app, &laptop, laptops_device, 7).await;
    sign_in_device(&app, &beside, besides_device, 8).await;
    let phone = another_browser(&app, &laptop).await;

    let (revoked, _) = app
        .send(
            reqwest::Method::POST,
            &phone,
            &format!("/api/keys/devices/{laptops_device}/revoke"),
            Value::Null,
        )
        .await;
    let (laptops_api, _) = app.get(&laptop, "/userinfo").await;
    let (besides_api, _) = app.get(&beside, "/userinfo").await;
    let besides_renewal = instances.refresh(&app, &beside.refresh_token).await;
    let back = authorize(&app, &app.the_request(), &laptop.cookie).await;
    let (phones_api, _) = app.get(&phone, "/userinfo").await;
    let (_, listed) = app.get(&phone, "/api/keys/devices").await;

    assert_eq!(revoked, 204);
    assert_eq!(
        [laptops_api, besides_api, besides_renewal].map(|s| s.as_u16()),
        [401, 401, 400],
        "the laptop's browser signs out, its other web app too"
    );
    assert!(
        location(&back).starts_with("/login?"),
        "its cookie signs no new device in without the password: {}",
        location(&back)
    );
    assert_eq!(phones_api, 200);
    let signed_in: Vec<_> = listed["devices"]
        .as_array()
        .unwrap()
        .iter()
        .map(|device| device["signed_in"].clone())
        .collect();
    assert_eq!(signed_in, [json!(false), json!(false)], "{listed}");
    assert_eq!(
        app.count("SELECT count(*) FROM sessions WHERE revoked_reason = 'device_revoked'")
            .await,
        3
    );
    app.stop().await.unwrap();
}

#[tokio::test]
async fn a_web_app_whose_storage_was_wiped_revokes_its_session_and_signs_in_again_silently() {
    let app = spawn_app().await;
    let official = app.sign_up("alice").await;
    let instances = OtherWebApp::start().await;
    let beside = instances.sign_in(&app, &official).await;
    let (before, after) = (Uuid::new_v4(), Uuid::new_v4());
    sign_in_device(&app, &official, before, 7).await;

    // Its storage wiped, the app is a new device on the session that named the old one.
    let (mismatch, refusal) = app
        .send(
            reqwest::Method::POST,
            &official,
            "/api/keys/devices",
            json!({
                "device_id": after,
                "drk_public_key": base64::engine::general_purpose::STANDARD.encode([9; 32]),
            }),
        )
        .await;
    let revoked = app
        .http
        .post(format!("{}/revoke", app.address))
        .form(&[
            ("client_id", app.client_id.as_str()),
            ("token", official.refresh_token.as_str()),
        ])
        .send()
        .await
        .unwrap()
        .status();
    let again = signed_in_again(&app, &official).await;
    let (registered, linked, _) = sign_in_device(&app, &again, after, 9).await;
    let (besides_api, _) = app.get(&beside, "/userinfo").await;
    let (old_token, _) = app.get(&official, "/userinfo").await;

    assert_eq!(
        (mismatch.as_u16(), refusal["error"].as_str()),
        (403, Some("device_mismatch"))
    );
    assert_eq!(revoked, 200);
    assert_eq!(
        [registered, linked].map(|s| s.as_u16()),
        [201, 204],
        "a session of its own, no password asked"
    );
    assert_eq!(besides_api, 200, "the other web app stays signed in");
    assert_eq!(old_token, 401);
    app.stop().await.unwrap();
}

/// What an access token says of itself: its claims, unverified.
fn claims(token: &str) -> Value {
    let payload = token.split('.').nth(1).expect("a JWT");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn the_password_typed_again_signs_the_web_app_in_anew_on_its_own_session() {
    let app = spawn_app().await;
    let signed_up = app.sign_up("alice").await;
    let device = Uuid::new_v4();
    sign_in_device(&app, &signed_up, device, 7).await;
    // An hour on: the password is no longer recent.
    app.execute("UPDATE sessions SET authenticated_at = now() - interval '1 hour'")
        .await;
    let (_, renewed) = app.refresh(&signed_up.refresh_token).await;
    let stale = Account {
        token: renewed["access_token"].as_str().unwrap().to_owned(),
        refresh_token: renewed["refresh_token"].as_str().unwrap().to_owned(),
        ..signed_up.clone()
    };
    let sign_out_others = async |who: &Account| {
        app.http
            .delete(format!("{}/api/sessions?keep=current", app.address))
            .bearer_auth(&who.token)
            .send()
            .await
            .unwrap()
            .status()
    };
    let refused = sign_out_others(&stale).await;

    let mut asked = app.the_request();
    asked.push(("prompt", "login".to_owned()));
    let shown = authorize(&app, &asked, &stale.cookie).await;
    let signed_in = app
        .http
        .post(format!("{}/login", app.address))
        .form(
            &[
                app.the_request(),
                vec![
                    ("email", stale.email.clone()),
                    ("password", PASSWORD.to_owned()),
                ],
            ]
            .concat(),
        )
        .header("cookie", &stale.cookie)
        .send()
        .await
        .unwrap();
    let tokens = app
        .tokens_for(&query_of(&location(&signed_in))["code"])
        .await;
    let fresh = Account {
        token: tokens["access_token"].as_str().unwrap().to_owned(),
        refresh_token: tokens["refresh_token"].as_str().unwrap().to_owned(),
        ..stale.clone()
    };
    let (named_again, _) = name_device(&app, &fresh, device).await;
    let allowed = sign_out_others(&fresh).await;

    assert_eq!(refused, 401, "insufficient_user_authentication");
    assert!(
        location(&shown).starts_with("/login?"),
        "{}",
        location(&shown)
    );
    let (before, after) = (claims(&stale.token), claims(&fresh.token));
    assert_eq!(
        after["sid"], before["sid"],
        "the web app's own session, reused"
    );
    assert!(
        after["auth_time"].as_i64().unwrap() >= before["auth_time"].as_i64().unwrap() + 3000,
        "{before} {after}"
    );
    assert_eq!(named_again, 204, "its device still named");
    assert_eq!(allowed, 204);
    app.stop().await.unwrap();
}
