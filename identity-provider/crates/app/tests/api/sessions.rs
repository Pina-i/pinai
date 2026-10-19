use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::helpers::{
    Account, CHALLENGE, PASSWORD, TestApp, VERIFIER, location, query_of, spawn_app,
};

/// A WebSocket opened with `token`: the stream past the handshake, or the refusal's status line.
async fn open_socket(app: &TestApp, token: &str) -> Result<TcpStream, String> {
    let mut socket = TcpStream::connect(app.domain.as_str()).await.unwrap();
    let upgrade = format!(
        "GET /ws?token={token} HTTP/1.1\r\nHost: {}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
         Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
        app.domain
    );
    socket.write_all(upgrade.as_bytes()).await.unwrap();
    let mut handshake = [0u8; 1024];
    let read = socket.read(&mut handshake).await.unwrap();
    let answer = String::from_utf8_lossy(&handshake[..read]).into_owned();
    if answer.starts_with("HTTP/1.1 101") {
        Ok(socket)
    } else {
        Err(answer.lines().next().unwrap_or_default().to_owned())
    }
}

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

/// Reads the socket to its end: whether the server closed it with 1008.
async fn closed_as_ended(socket: &mut TcpStream) -> bool {
    let mut frames = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), socket.read_to_end(&mut frames))
        .await
        .expect("the socket was closed")
        .unwrap();
    frames
        .windows(4)
        .any(|w| w[0] == 0x88 && u16::from_be_bytes([w[2], w[3]]) == 1008)
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
