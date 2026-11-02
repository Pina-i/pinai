use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::{Context, Layer, SubscriberExt};

use super::*;

/// Counts the events at WARN or above.
#[derive(Clone, Default)]
struct Loud(Arc<AtomicUsize>);

impl<S: Subscriber> Layer<S> for Loud {
    fn on_event(&self, event: &Event<'_>, _: Context<'_, S>) {
        if *event.metadata().level() <= Level::WARN {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
}

/// A peer on the loopback interface answering every request 403.
async fn a_refusing_peer() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let at = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let mut request = [0; 4096];
            let _ = socket.read(&mut request).await;
            let body = r#"{"error":"access_denied"}"#;
            let response = format!(
                "HTTP/1.1 403 Forbidden\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = socket.write_all(response.as_bytes()).await;
        }
    });
    format!("http://{at}/users/bob_k2m9x/inbox")
}

#[tokio::test]
async fn a_peers_refusal_is_returned_not_logged() {
    let loud = Loud::default();
    let _guard =
        tracing::subscriber::set_default(tracing_subscriber::registry().with(loud.clone()));
    let signing_key = SigningKey::from_bytes(&[7; 32]);
    let signer = Signer {
        key_id: "http://localhost:8080/users/alice_k2m9x#main-key",
        signing_key: &signing_key,
    };

    let refused = signed_post(
        &signer,
        &a_refusing_peer().await,
        b"{}",
        "application/activity+json",
        UrlPolicy::from_issuer("http://localhost:8080"),
    )
    .await;

    assert!(
        matches!(&refused, Err(TransportError::Upstream(reason)) if reason.starts_with("peer returned 403")),
        "{refused:?}"
    );
    assert_eq!(
        loud.0.load(Ordering::SeqCst),
        0,
        "the caller logs what it makes of it"
    );
}

#[tokio::test]
async fn a_signed_request_leaves_its_host_to_the_client() {
    let signing_key = SigningKey::from_bytes(&[7; 32]);
    let signer = Signer {
        key_id: "http://localhost:8080/users/alice_k2m9x#main-key",
        signing_key: &signing_key,
    };
    let policy = UrlPolicy::from_issuer("http://localhost:8080");

    let post = signed_post_request(
        &signer,
        "http://localhost:8081/users/bob_k2m9x/inbox",
        b"{}",
        "application/activity+json",
        policy,
    )
    .await
    .unwrap();
    let get = signed_get_request(&signer, "http://localhost:8081/media/a1", policy)
        .await
        .unwrap();

    for request in [post, get] {
        assert!(
            request.headers().get(reqwest::header::HOST).is_none(),
            "over HTTP/2 nginx refuses a Host header beside :authority"
        );
    }
}

/// A peer on the loopback interface that accepts one request and hands back its head.
async fn a_listening_peer() -> (String, tokio::task::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let at = listener.local_addr().unwrap();
    let received = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = [0; 4096];
        let read = socket.read(&mut request).await.unwrap();
        let response = "HTTP/1.1 202 Accepted\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";
        socket.write_all(response.as_bytes()).await.unwrap();
        String::from_utf8_lossy(&request[..read]).into_owned()
    });
    (format!("http://{at}/users/bob_k2m9x/inbox"), received)
}

#[tokio::test]
async fn a_signed_post_verifies_against_the_host_the_client_writes() {
    let signing_key = SigningKey::from_bytes(&[7; 32]);
    let signer = Signer {
        key_id: "http://localhost:8080/users/alice_k2m9x#main-key",
        signing_key: &signing_key,
    };
    let (inbox, received) = a_listening_peer().await;

    signed_post(
        &signer,
        &inbox,
        b"{}",
        "application/activity+json",
        UrlPolicy::from_issuer("http://localhost:8080"),
    )
    .await
    .unwrap();

    let head = received.await.unwrap();
    let mut lines = head.split("\r\n");
    let path = lines.next().unwrap().split(' ').nth(1).unwrap().to_owned();
    let headers: Vec<(String, String)> = lines
        .take_while(|line| !line.is_empty())
        .filter_map(|line| line.split_once(": "))
        .map(|(name, value)| (name.to_ascii_lowercase(), value.to_owned()))
        .collect();
    let header = |name: &str| {
        headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.clone())
    };
    assert_eq!(headers.iter().filter(|(n, _)| n == "host").count(), 1);
    http_signatures::verify_request_with_key(
        "post",
        &path,
        &header("signature").unwrap(),
        header,
        &signing_key.verifying_key(),
    )
    .unwrap();
}
