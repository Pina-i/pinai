//! Verifying-key cache for inbound HTTP Signature checks.
//!
//! Correctness under key rotation comes from refetching when a *verification*
//! fails, not from a short TTL — so the TTL here is only a garbage-collection
//! bound and can be long. That refetch path is reachable by anyone who sends a
//! bad signature for a cached `keyId`, so it is rate limited per key; without
//! that limit an attacker can both disable the cache and use it to amplify
//! requests at a host of their choosing.

use std::time::Duration;

use ed25519_dalek::pkcs8::DecodePublicKey;
use ed25519_dalek::VerifyingKey;
use moka::future::Cache;
use tracing::{debug, warn};

use crate::error::TransportError;
use crate::http::{get_json_screened, UrlPolicy};

/// Long enough that the cache does real work; rotation is handled by
/// [`KeyCache::refetch`], not by waiting for this to lapse.
const VERIFIED_TTL: Duration = Duration::from_secs(6 * 60 * 60);
/// Short-lived, and covers failures too: `keyId` is attacker-chosen, so one
/// pointing at a dead or slow host must not cost a fetch on every request.
const FETCH_TTL: Duration = Duration::from_secs(60);
/// Minimum interval between forced refetches of the same key.
const REFETCH_INTERVAL: Duration = Duration::from_secs(60);
/// `keyId` is attacker-controlled, so the entry count is capped.
const MAX_ENTRIES: u64 = 10_000;

pub struct KeyCache {
    /// Keys that have verified a real signature. Only [`KeyCache::store_verified`]
    /// writes here, so every entry corresponds to a peer that actually proved
    /// possession of the key.
    verified: Cache<String, VerifyingKey>,
    /// Short-lived fetch results, successes and failures alike. Also collapses
    /// concurrent misses for one key into a single outbound request.
    fetched: Cache<String, Result<VerifyingKey, String>>,
    /// Presence of a key means it was refetched recently.
    refetch_guard: Cache<String, ()>,
    policy: UrlPolicy,
}

impl KeyCache {
    pub fn new(policy: UrlPolicy) -> Self {
        Self {
            verified: Cache::builder()
                .max_capacity(MAX_ENTRIES)
                .time_to_live(VERIFIED_TTL)
                .build(),
            fetched: Cache::builder()
                .max_capacity(MAX_ENTRIES)
                .time_to_live(FETCH_TTL)
                .build(),
            refetch_guard: Cache::builder()
                .max_capacity(MAX_ENTRIES)
                .time_to_live(REFETCH_INTERVAL)
                .build(),
            policy,
        }
    }

    /// A key to try first: the verified one if present, otherwise a fetch.
    ///
    /// Returns whether the key came from the verified cache, which decides
    /// whether a failed verification is worth a refetch.
    pub async fn get(&self, key_id: &str) -> Result<(VerifyingKey, bool), TransportError> {
        if let Some(key) = self.verified.get(key_id).await {
            return Ok((key, true));
        }
        Ok((self.fetch_coalesced(key_id).await?, false))
    }

    /// Re-read a key whose cached copy just failed to verify, at most once per
    /// [`REFETCH_INTERVAL`] per key.
    pub async fn refetch(&self, key_id: &str) -> Result<VerifyingKey, TransportError> {
        if self.refetch_guard.get(key_id).await.is_some() {
            return Err(TransportError::Denied(
                "signature verification failed and this key was refetched too recently".into(),
            ));
        }
        self.refetch_guard.insert(key_id.to_string(), ()).await;

        debug!(%key_id, "refetching key after a verification failure");
        self.verified.invalidate(key_id).await;
        self.fetched.invalidate(key_id).await;
        self.fetch_coalesced(key_id).await
    }

    /// Promote a key that has now verified a real signature.
    pub async fn store_verified(&self, key_id: &str, key: VerifyingKey) {
        self.verified.insert(key_id.to_string(), key).await;
    }

    async fn fetch_coalesced(&self, key_id: &str) -> Result<VerifyingKey, TransportError> {
        let policy = self.policy;
        let owned = key_id.to_string();

        // `get_with` caches whatever the loader returns, so the error arm is
        // stored too — that is the negative cache.
        let outcome = self
            .fetched
            .get_with(owned.clone(), async move {
                fetch_key(&owned, policy).await.map_err(|e| e.to_string())
            })
            .await;

        outcome.map_err(TransportError::Upstream)
    }
}

/// Fetch the actor document named by `keyId` and parse out its public key.
async fn fetch_key(key_id: &str, policy: UrlPolicy) -> Result<VerifyingKey, TransportError> {
    let actor_url = key_id
        .split('#')
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| TransportError::BadRequest("invalid keyId format".into()))?;

    let actor_doc = get_json_screened(actor_url, "application/activity+json", policy).await?;

    let pem = actor_doc
        .get("publicKey")
        .and_then(|pk| pk.get("publicKeyPem"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| TransportError::BadRequest("actor has no publicKeyPem".into()))?;

    VerifyingKey::from_public_key_pem(pem).map_err(|e| {
        warn!(%key_id, "actor publicKeyPem did not parse");
        TransportError::BadRequest(format!("actor publicKeyPem did not parse: {e}"))
    })
}

#[cfg(test)]
mod tests;
