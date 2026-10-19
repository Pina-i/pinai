use std::time::Duration;

use futures_util::{StreamExt, stream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::oneshot;

use crate::helpers::{PASSWORD, spawn_app};

#[tokio::test]
async fn a_request_under_way_is_answered_before_the_instance_stops() {
    let app = spawn_app().await;
    let alice = app.sign_up("alice").await;
    let form = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("email", alice.email.as_str()),
            ("password", PASSWORD),
            ("client_id", app.client_id.as_str()),
            ("redirect_uri", app.redirect_uri.as_str()),
            ("scope", "openid"),
            ("state", "s"),
            (
                "code_challenge",
                "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            ),
            ("code_challenge_method", "S256"),
        ])
        .finish();
    // The body's end is held back: the request stays under way until the test lets it go.
    let (head, tail) = form.split_at(10);
    let (release, released) = oneshot::channel::<()>();
    let body = stream::iter([Ok::<_, std::io::Error>(head.to_owned())]).chain(stream::once({
        let tail = tail.to_owned();
        async move {
            let _ = released.await;
            Ok(tail)
        }
    }));
    let signing_in = tokio::spawn(
        app.http
            .post(format!("{}/login", app.address))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(reqwest::Body::wrap_stream(body))
            .send(),
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    let address = app.address.clone();

    let stopping = tokio::spawn(app.stop());
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        !stopping.is_finished(),
        "the instance stopped with a request under way"
    );
    release.send(()).unwrap();

    let answered = signing_in.await.unwrap().expect("the sign-in was answered");
    assert_eq!(answered.status(), 303);
    tokio::time::timeout(Duration::from_secs(15), stopping)
        .await
        .expect("stopped once the request was answered")
        .unwrap()
        .unwrap();
    assert!(
        reqwest::get(format!("{address}/health")).await.is_err(),
        "a stopped instance takes no connection"
    );
}

#[tokio::test]
async fn an_open_websocket_is_closed_as_going_away() {
    let app = spawn_app().await;
    let alice = app.sign_up("alice").await;
    let mut socket = TcpStream::connect(app.domain.as_str()).await.unwrap();
    let upgrade = format!(
        "GET /ws?token={} HTTP/1.1\r\nHost: {}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
         Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
        alice.token, app.domain
    );
    socket.write_all(upgrade.as_bytes()).await.unwrap();
    let mut handshake = [0u8; 1024];
    let read = socket.read(&mut handshake).await.unwrap();
    assert!(
        String::from_utf8_lossy(&handshake[..read]).starts_with("HTTP/1.1 101"),
        "{}",
        String::from_utf8_lossy(&handshake[..read])
    );

    let stopping = tokio::spawn(app.stop());
    let mut frames = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), socket.read_to_end(&mut frames))
        .await
        .expect("the socket was closed")
        .unwrap();

    // A close frame, `0x88`, whose code is 1001: going away.
    let close = frames
        .windows(4)
        .position(|w| w[0] == 0x88 && u16::from_be_bytes([w[2], w[3]]) == 1001);
    assert!(close.is_some(), "{frames:02x?}");
    tokio::time::timeout(Duration::from_secs(15), stopping)
        .await
        .expect("stopped within the drain")
        .unwrap()
        .unwrap();
}
