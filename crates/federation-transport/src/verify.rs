use http::HeaderMap;

use crate::error::TransportError;
use crate::keycache::KeyCache;

/// Verify an incoming HTTP Signature against the signer's published key.
///
/// Returns the verified `keyId` (e.g. `https://idp.alice.com/actor#main-key`),
/// from which callers derive the requesting peer's actor URI.
///
/// A key from the cache that fails to verify is treated as possibly rotated,
/// not as a forgery: it is refetched once (rate limited per key) and retried
/// before the request is rejected.
pub async fn verify_http_signature(
    cache: &KeyCache,
    headers: &HeaderMap,
    method: &str,
    path: &str,
) -> Result<String, TransportError> {
    let sig_header = headers
        .get("signature")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| TransportError::BadRequest("missing Signature header".into()))?;

    let parsed = http_signatures::parse_signature_header(sig_header)
        .map_err(|e| TransportError::BadRequest(format!("invalid Signature header: {e}")))?;
    let key_id = parsed.key_id;

    let get_header = |name: &str| -> Option<String> {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    };

    let (key, from_cache) = cache.get(&key_id).await?;

    let denied = |e: http_signatures::VerifyError| {
        TransportError::Denied(format!("signature verification failed: {e}"))
    };

    match http_signatures::verify_request_with_key(method, path, sig_header, get_header, &key) {
        Ok(()) => {
            cache.store_verified(&key_id, key).await;
            Ok(key_id)
        }
        Err(_) if from_cache => {
            let fresh = cache.refetch(&key_id).await?;
            http_signatures::verify_request_with_key(method, path, sig_header, get_header, &fresh)
                .map_err(denied)?;
            cache.store_verified(&key_id, fresh).await;
            Ok(key_id)
        }
        Err(e) => Err(denied(e)),
    }
}

/// Verify the `Digest` header covers, and matches, the received body.
///
/// [`http_signatures::verify_request`] rebuilds the signing string from header
/// *values*, so a valid signature proves the sender signed some `Digest` value —
/// never that the body which arrived hashes to it. Both checks below are needed:
/// without the coverage check an attacker appends their own `Digest`, and
/// without the comparison a captured request is replayed with a swapped body.
pub fn verify_body_digest(headers: &HeaderMap, body: &[u8]) -> Result<(), TransportError> {
    let sig_header = headers
        .get("signature")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| TransportError::BadRequest("missing Signature header".into()))?;

    let parsed = http_signatures::parse_signature_header(sig_header)
        .map_err(|e| TransportError::BadRequest(format!("invalid Signature header: {e}")))?;

    if !parsed
        .headers
        .iter()
        .any(|h| h.eq_ignore_ascii_case("digest"))
    {
        return Err(TransportError::Denied(
            "signature does not cover the Digest header".into(),
        ));
    }

    let received = headers
        .get("digest")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| TransportError::BadRequest("missing Digest header".into()))?;

    if received != http_signatures::sha256_digest(body) {
        return Err(TransportError::Denied(
            "Digest does not match request body".into(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests;
