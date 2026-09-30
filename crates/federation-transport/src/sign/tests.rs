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
