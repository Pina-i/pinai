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
