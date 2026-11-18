use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::*;

/// A peer on the loopback interface that answers every request with `response`.
async fn peer(response: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let mut request = vec![0; 8192];
            let _ = socket.read(&mut request).await;
            let _ = socket.write_all(response.as_bytes()).await;
            let _ = socket.shutdown().await;
        }
    });
    address
}

fn actors() -> FederatedRemoteActors {
    // Never reached: a refused resolution stops before anything is remembered.
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://nobody@127.0.0.1:1/none")
        .unwrap();
    FederatedRemoteActors::new(
        pool,
        "http".to_owned(),
        UrlPolicy::from_issuer("http://localhost:8080"),
    )
}

#[tokio::test]
async fn an_instance_answering_webfinger_with_junk_is_unavailable() {
    let address = peer(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
    )
    .await;
    let dave = FederatedAddress::parse(&format!("dave_k2m9x@{address}")).unwrap();

    let refused = actors().resolve(&dave).await;

    assert!(
        matches!(refused, Err(RemoteActorsError::Unavailable(_))),
        "{refused:?}"
    );
}

#[tokio::test]
async fn an_instance_answering_past_the_body_cap_is_unavailable_not_refused() {
    let padding = " ".repeat(300 * 1024);
    let oversized = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{{}}{padding}"
    );
    let address = peer(Box::leak(oversized.into_boxed_str())).await;
    let dave = FederatedAddress::parse(&format!("dave_k2m9x@{address}")).unwrap();

    let refused = actors().resolve(&dave).await;

    assert!(
        matches!(&refused, Err(RemoteActorsError::Unavailable(m)) if m.contains("byte cap")),
        "{refused:?}"
    );
}

#[tokio::test]
async fn an_instance_that_does_not_know_the_account_says_so() {
    let address =
        peer("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
    let dave = FederatedAddress::parse(&format!("dave_k2m9x@{address}")).unwrap();

    let refused = actors().resolve(&dave).await;

    assert!(
        matches!(refused, Err(RemoteActorsError::NotFound)),
        "{refused:?}"
    );
}

/// A peer on the loopback interface answering WebFinger with the first of what `answers` gives
/// for the address it listens at, and any other request with the second.
async fn a_peer_answering(
    answers: impl FnOnce(&str) -> (serde_json::Value, serde_json::Value),
) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (finger, document) = answers(&address.to_string());
    let answer = |body: &serde_json::Value| {
        let body = body.to_string();
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n{body}",
            body.len()
        )
    };
    let (finger, document) = (answer(&finger), answer(&document));
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let mut request = vec![0; 8192];
            let read = socket.read(&mut request).await.unwrap_or(0);
            let asked = String::from_utf8_lossy(&request[..read]);
            let response = if asked.contains("webfinger") {
                &finger
            } else {
                &document
            };
            let _ = socket.write_all(response.as_bytes()).await;
            let _ = socket.shutdown().await;
        }
    });
    address
}

/// Dave's WebFinger answer and document at `actor`, with `inbox`.
fn dave_as(actor: &str, inbox: &str) -> (serde_json::Value, serde_json::Value) {
    let finger = serde_json::json!({
        "subject": "acct:dave_k2m9x",
        "links": [{ "rel": "self", "type": "application/activity+json", "href": actor }],
    });
    let mut document = serde_json::to_value(activitypub::Actor::person(
        "http://unused",
        "dave_k2m9x",
        "Dave",
        "-----BEGIN PUBLIC KEY-----",
    ))
    .unwrap();
    document["id"] = serde_json::json!(actor);
    document["inbox"] = serde_json::json!(inbox);
    (finger, document)
}

#[tokio::test]
async fn an_answer_this_instance_would_not_store_is_unavailable_and_nothing_is_remembered() {
    let long = "d".repeat(ActorUri::MAX_BYTES);
    for (actor, inbox) in [
        ("http://{at}/users/dave_k2m9x?page=1", "http://{at}/inbox"),
        ("http://dave@{at}/users/dave_k2m9x", "http://{at}/inbox"),
        ("http://{at}/users/{long}", "http://{at}/inbox"),
        ("http://{at}/users/dave_k2m9x", "http://{at}/{long}"),
    ] {
        let address = a_peer_answering(|at| {
            let filled = |template: &str| template.replace("{at}", at).replace("{long}", &long);
            dave_as(&filled(actor), &filled(inbox))
        })
        .await;
        let dave = FederatedAddress::parse(&format!("dave_k2m9x@{address}")).unwrap();

        let refused = actors().resolve(&dave).await;

        assert!(
            matches!(refused, Err(RemoteActorsError::Unavailable(_))),
            "{actor} {inbox}: {refused:?}"
        );
    }
}
