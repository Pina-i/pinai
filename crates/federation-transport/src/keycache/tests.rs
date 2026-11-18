use super::*;
use ed25519_dalek::SigningKey;

/// Production policy, so every keyId below is screened out before any
/// network call is attempted.
fn cache() -> KeyCache {
    KeyCache::new(UrlPolicy {
        require_https: true,
        allow_private_networks: false,
    })
}

fn a_key() -> VerifyingKey {
    SigningKey::from_bytes(&[7u8; 32]).verifying_key()
}

const KEY_ID: &str = "https://idp.bob.com/users/bob#main-key";

#[tokio::test]
async fn a_verified_key_is_served_from_cache() {
    let c = cache();
    c.store_verified(KEY_ID, a_key()).await;

    let (key, from_cache) = c.get(KEY_ID).await.unwrap();
    assert_eq!(key, a_key());
    assert!(
        from_cache,
        "should be flagged as cached so rotation can refetch"
    );
}

/// The abuse vector the limiter exists for: anyone can send a bad signature
/// for a cached keyId, and each one would otherwise force an outbound fetch.
#[tokio::test]
async fn refetch_is_rate_limited_per_key() {
    let c = cache();

    // First refetch is permitted — it fails on the URL screen, not the guard.
    let first = c.refetch(KEY_ID).await;
    assert!(first.is_err());

    let second = c.refetch(KEY_ID).await;
    assert!(
        matches!(&second, Err(TransportError::Denied(m)) if m.contains("refetched too recently")),
        "second refetch inside the window must be refused by the guard, got {second:?}"
    );
}

#[tokio::test]
async fn the_refetch_limit_is_scoped_to_one_key() {
    let c = cache();
    let _ = c.refetch(KEY_ID).await;

    let other = c
        .refetch("https://idp.carol.com/users/carol#main-key")
        .await;
    assert!(
        !matches!(&other, Err(TransportError::Denied(m)) if m.contains("refetched too recently")),
        "a different key must not be blocked by another key's guard"
    );
}

#[tokio::test]
async fn refetch_drops_the_stale_verified_entry() {
    let c = cache();
    c.store_verified(KEY_ID, a_key()).await;

    let _ = c.refetch(KEY_ID).await;

    // The refetch failed, so nothing replaced it — the stale key must be gone
    // rather than left to satisfy later requests.
    assert!(c.verified.get(KEY_ID).await.is_none());
}

#[tokio::test]
async fn a_failed_fetch_is_negatively_cached() {
    let c = cache();
    assert!(c.get(KEY_ID).await.is_err());
    assert!(
        c.fetched.get(KEY_ID).await.is_some(),
        "the failure should be cached so a dead keyId costs one fetch, not one per request"
    );
}

/// Serves on `listener`: `/users/dave` answers `302` to `moved_to`, any other path an actor
/// document publishing `key`.
fn serve_dave(listener: tokio::net::TcpListener, moved_to: String, key: VerifyingKey) {
    use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
    use ed25519_dalek::pkcs8::EncodePublicKey;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let pem = key.to_public_key_pem(LineEnding::LF).unwrap();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let mut request = [0; 4096];
            let read = socket.read(&mut request).await.unwrap_or(0);
            let request = String::from_utf8_lossy(&request[..read]);
            let response = if request.split(' ').nth(1) == Some("/users/dave") {
                format!(
                    "HTTP/1.1 302 Found\r\nlocation: {moved_to}\r\ncontent-length: 0\r\n\
                     connection: close\r\n\r\n"
                )
            } else {
                let body = serde_json::json!({ "publicKey": { "publicKeyPem": pem } }).to_string();
                format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                )
            };
            let _ = socket.write_all(response.as_bytes()).await;
        }
    });
}

fn a_dev_cache() -> KeyCache {
    KeyCache::new(UrlPolicy::from_issuer("http://localhost"))
}

#[tokio::test]
async fn a_key_another_instance_serves_through_a_redirect_is_refused() {
    let victim = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let evil = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (at, evil_at) = (victim.local_addr().unwrap(), evil.local_addr().unwrap());
    serve_dave(evil, "/".to_owned(), a_key());
    serve_dave(victim, format!("http://{evil_at}/keys/dave"), a_key());

    let refused = a_dev_cache()
        .get(&format!("http://{at}/users/dave#main-key"))
        .await;

    assert!(
        matches!(&refused, Err(TransportError::Upstream(m)) if m.contains("off its origin")),
        "{refused:?}"
    );
}

#[tokio::test]
async fn a_key_moved_within_its_instance_is_still_read() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let at = listener.local_addr().unwrap();
    serve_dave(listener, "/keys/dave".to_owned(), a_key());

    let (key, from_cache) = a_dev_cache()
        .get(&format!("http://{at}/users/dave#main-key"))
        .await
        .unwrap();

    assert_eq!(key, a_key());
    assert!(!from_cache);
}
