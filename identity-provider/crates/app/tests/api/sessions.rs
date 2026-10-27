use std::time::Duration;

use tokio::io::AsyncReadExt;

use crate::helpers::{
    Account, CHALLENGE, PASSWORD, TestApp, VERIFIER, closed_as_ended, location, open_socket,
    query_of, spawn_app,
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
async fn signing_out_of_the_browser_ends_the_web_clients_refresh_tokens_not_the_desktops() {
    let app = spawn_app().await;
    let alice = app.sign_up("alice").await;
    let desktop = format!("{}/clients/desktop.json", app.address);
    let signed_in = app
        .http
        .post(format!("{}/login", app.address))
        .form(&[
            ("email", alice.email.as_str()),
            ("password", PASSWORD),
            ("client_id", &desktop),
            ("redirect_uri", "io.github.pina-i:/callback"),
            ("scope", "openid profile email offline_access"),
            ("state", "desktop-state"),
            ("code_challenge", CHALLENGE),
            ("code_challenge_method", "S256"),
        ])
        .header("cookie", &alice.cookie)
        .send()
        .await
        .unwrap();
    let callback = location(&signed_in);
    assert!(
        callback.starts_with("io.github.pina-i:/callback?"),
        "{callback}"
    );
    let tokens: serde_json::Value = app
        .http
        .post(format!("{}/token", app.address))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", query_of(&callback)["code"].as_str()),
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

    app.http
        .get(format!("{}/logout", app.address))
        .header("cookie", &alice.cookie)
        .send()
        .await
        .unwrap();
    let (web, _) = app.refresh(&alice.refresh_token).await;
    let (desktop_api, _) = app.get(&on_desktop, "/userinfo").await;
    let desktop_refresh = app
        .http
        .post(format!("{}/token", app.address))
        .form(&[
            ("grant_type", "refresh_token"),
            ("client_id", desktop.as_str()),
            ("refresh_token", tokens["refresh_token"].as_str().unwrap()),
        ])
        .send()
        .await
        .unwrap()
        .status();

    assert_eq!(
        web, 400,
        "the web client's chain hung off the browser's session"
    );
    assert_eq!(desktop_api, 200, "the desktop has a session of its own");
    assert_eq!(desktop_refresh, 200);
    assert_eq!(
        app.count("SELECT count(*) FROM sessions WHERE kind = 'app' AND revoked_at IS NULL")
            .await,
        1
    );
    app.stop().await.unwrap();
}

/// Another browser signing in to `who`'s account with the password: a session of its own.
async fn another_browser(app: &TestApp, who: &Account) -> Account {
    let signed_in = app
        .form("/login", &[("email", &who.email), ("password", PASSWORD)])
        .await;
    let landed = location(&signed_in);
    assert!(landed.starts_with(&app.redirect_uri), "{landed}");
    let tokens = app.tokens_for(&query_of(&landed)["code"]).await;
    Account {
        token: tokens["access_token"].as_str().unwrap().to_owned(),
        refresh_token: tokens["refresh_token"].as_str().unwrap().to_owned(),
        cookie: signed_in.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned(),
        ..who.clone()
    }
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
        1
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
