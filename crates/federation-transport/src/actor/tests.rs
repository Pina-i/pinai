use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::*;

/// A peer on the loopback interface answering WebFinger for `dave` and his actor document.
async fn a_peer(icon: serde_json::Value) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let at = listener.local_addr().unwrap();
    let actor = format!("http://{at}/users/dave");
    let finger = serde_json::json!({
        "subject": format!("acct:dave@{at}"),
        "links": [{ "rel": "self", "type": "application/activity+json", "href": actor }],
    });
    let mut document = serde_json::to_value(Actor::person(
        &format!("http://{at}"),
        "dave",
        "Dave",
        "-----BEGIN PUBLIC KEY-----",
    ))
    .unwrap();
    document["icon"] = icon;
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let (finger, document) = (finger.to_string(), document.to_string());
            tokio::spawn(async move {
                let mut request = [0; 4096];
                let read = socket.read(&mut request).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&request[..read]);
                let body = if request.contains("webfinger") {
                    finger
                } else {
                    document
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                     content-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
            });
        }
    });
    at.to_string()
}

#[tokio::test]
async fn a_resolved_actor_brings_the_avatar_its_document_gives() {
    let domain =
        a_peer(serde_json::json!({ "type": "Image", "url": "https://cdn.test/dave.png" })).await;

    let dave = resolve_remote_actor(
        "dave",
        &domain,
        "http",
        UrlPolicy::from_issuer("http://localhost"),
    )
    .await
    .unwrap();

    assert_eq!(dave.display_name.as_deref(), Some("Dave"));
    assert_eq!(
        dave.avatar_url.as_deref(),
        Some("https://cdn.test/dave.png")
    );
}

#[tokio::test]
async fn an_icon_given_as_a_list_brings_its_first_image() {
    let domain = a_peer(serde_json::json!([
        { "type": "Image", "url": "https://cdn.test/first.png" },
        { "type": "Image", "url": "https://cdn.test/second.png" },
    ]))
    .await;

    let dave = resolve_remote_actor(
        "dave",
        &domain,
        "http",
        UrlPolicy::from_issuer("http://localhost"),
    )
    .await
    .unwrap();

    assert_eq!(
        dave.avatar_url.as_deref(),
        Some("https://cdn.test/first.png")
    );
}
