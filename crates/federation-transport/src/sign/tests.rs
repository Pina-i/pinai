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

/// A peer on the loopback interface answering every request `307` to `/elsewhere`, counting them.
async fn a_redirecting_peer() -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let at = listener.local_addr().unwrap();
    let asked = Arc::new(AtomicUsize::new(0));
    let counted = asked.clone();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let mut request = [0; 4096];
            let _ = socket.read(&mut request).await;
            counted.fetch_add(1, Ordering::SeqCst);
            let response = "HTTP/1.1 307 Temporary Redirect\r\nlocation: /elsewhere\r\n\
                            content-length: 0\r\nconnection: close\r\n\r\n";
            let _ = socket.write_all(response.as_bytes()).await;
        }
    });
    (format!("http://{at}/users/bob_k2m9x/inbox"), asked)
}

#[tokio::test]
async fn a_signed_post_follows_no_redirect() {
    let signing_key = SigningKey::from_bytes(&[7; 32]);
    let signer = Signer {
        key_id: "http://localhost:8080/users/alice_k2m9x#main-key",
        signing_key: &signing_key,
    };
    let (inbox, asked) = a_redirecting_peer().await;

    let refused = signed_post(
        &signer,
        &inbox,
        b"{}",
        "application/activity+json",
        UrlPolicy::from_issuer("http://localhost:8080"),
    )
    .await;

    assert!(
        matches!(&refused, Err(TransportError::Upstream(reason)) if reason.starts_with("peer returned 307")),
        "{refused:?}"
    );
    assert_eq!(asked.load(Ordering::SeqCst), 1);
}

/// A peer on the loopback interface answering `403` with a body that never ends.
async fn a_ranting_peer() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let at = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let _ = socket.read(&mut [0; 4096]).await;
            let head = "HTTP/1.1 403 Forbidden\r\ntransfer-encoding: chunked\r\n\r\n";
            if socket.write_all(head.as_bytes()).await.is_err() {
                continue;
            }
            let line = "denied\r\n\x1b[2Jforged log line\n";
            let chunk = format!("{:x}\r\n{line}\r\n", line.len());
            while socket.write_all(chunk.as_bytes()).await.is_ok() {}
        }
    });
    format!("http://{at}/users/bob_k2m9x/inbox")
}

#[tokio::test]
async fn a_peers_refusal_is_cut_to_one_short_line_without_reading_it_all() {
    let signing_key = SigningKey::from_bytes(&[7; 32]);
    let signer = Signer {
        key_id: "http://localhost:8080/users/alice_k2m9x#main-key",
        signing_key: &signing_key,
    };

    let refused = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        signed_post(
            &signer,
            &a_ranting_peer().await,
            b"{}",
            "application/activity+json",
            UrlPolicy::from_issuer("http://localhost:8080"),
        ),
    )
    .await
    .expect("a refusal is not read to its end");

    let Err(TransportError::Upstream(reason)) = refused else {
        panic!("{refused:?}");
    };
    assert!(
        reason.starts_with("peer returned 403 Forbidden: denied [2Jforged log line denied"),
        "{reason}"
    );
    assert!(reason.ends_with('…'), "{reason}");
    assert!(
        !reason.chars().any(char::is_control) && reason.chars().count() < 260,
        "{reason}"
    );
}

/// A peer on the loopback interface that answers `head` at once, then `rest` after `delay`.
async fn a_slow_peer(head: &'static str, delay: std::time::Duration, rest: &'static str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let at = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let _ = socket.read(&mut [0; 4096]).await;
            let _ = socket.write_all(head.as_bytes()).await;
            tokio::time::sleep(delay).await;
            let _ = socket.write_all(rest.as_bytes()).await;
        }
    });
    format!("http://{at}/api/presence/batch")
}

async fn post_within(
    target: &str,
    deadline: std::time::Duration,
) -> Result<reqwest::Response, TransportError> {
    let signing_key = SigningKey::from_bytes(&[7; 32]);
    let signer = Signer {
        key_id: "http://localhost:8080/actor#main-key",
        signing_key: &signing_key,
    };
    send_signed_post_within(
        &signer,
        target,
        b"{}",
        "application/json",
        UrlPolicy::from_issuer("http://localhost:8080"),
        deadline,
    )
    .await
}

#[tokio::test]
async fn one_deadline_covers_a_signed_posts_answer() {
    let peer = a_slow_peer(
        "",
        std::time::Duration::from_millis(600),
        "HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}",
    )
    .await;

    let late = post_within(&peer, std::time::Duration::from_millis(300)).await;

    assert!(
        matches!(&late, Err(TransportError::Upstream(m)) if m.contains("took more than")),
        "{late:?}"
    );
}

#[tokio::test]
async fn one_deadline_covers_the_body_a_signed_posts_caller_reads() {
    let peer = a_slow_peer(
        "HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{",
        std::time::Duration::from_millis(600),
        "}",
    )
    .await;

    let answer = post_within(&peer, std::time::Duration::from_millis(300))
        .await
        .unwrap();
    let late = crate::http::read_capped(answer).await;

    assert!(late.is_err(), "{late:?}");
}
