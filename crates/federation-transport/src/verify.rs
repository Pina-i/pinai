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
mod tests {
    use super::*;
    use http::HeaderValue;

    const BODY: &[u8] = br#"{"type":"Follow","actor":"https://idp.bob.com/users/bob"}"#;

    /// `signature_bytes` is never inspected here — only `keyId` and `headers` are.
    fn sig_header(covered: &str) -> String {
        format!(
            r#"keyId="https://idp.bob.com/users/bob#main-key",headers="{covered}",signature="AAAA""#
        )
    }

    fn headers(sig: Option<&str>, digest: Option<&str>) -> HeaderMap {
        let mut h = HeaderMap::new();
        if let Some(s) = sig {
            h.insert("signature", HeaderValue::from_str(s).unwrap());
        }
        if let Some(d) = digest {
            h.insert("digest", HeaderValue::from_str(d).unwrap());
        }
        h
    }

    const SIGNED_WITH_DIGEST: &str = "(request-target) host date digest";

    #[test]
    fn accepts_a_digest_that_covers_and_matches_the_body() {
        let d = http_signatures::sha256_digest(BODY);
        let h = headers(Some(&sig_header(SIGNED_WITH_DIGEST)), Some(&d));
        assert!(verify_body_digest(&h, BODY).is_ok());
    }

    /// Replay with a swapped body: the signature is untouched and still covers
    /// `digest`, but the bytes that arrived no longer hash to it.
    #[test]
    fn rejects_a_body_that_does_not_match_the_digest() {
        let d = http_signatures::sha256_digest(BODY);
        let h = headers(Some(&sig_header(SIGNED_WITH_DIGEST)), Some(&d));
        assert!(verify_body_digest(&h, br#"{"type":"Follow","actor":"evil"}"#).is_err());
    }

    /// Digest present and correct, but outside the signed set — so an attacker
    /// can rewrite body and Digest together and the signature still verifies.
    #[test]
    fn rejects_a_digest_the_signature_does_not_cover() {
        let d = http_signatures::sha256_digest(BODY);
        let h = headers(Some(&sig_header("(request-target) host date")), Some(&d));
        assert!(verify_body_digest(&h, BODY).is_err());
    }

    #[test]
    fn accepts_digest_covered_under_any_casing() {
        let d = http_signatures::sha256_digest(BODY);
        let h = headers(
            Some(&sig_header("(request-target) host date Digest")),
            Some(&d),
        );
        assert!(verify_body_digest(&h, BODY).is_ok());
    }

    #[test]
    fn rejects_a_missing_digest_header() {
        let h = headers(Some(&sig_header(SIGNED_WITH_DIGEST)), None);
        assert!(verify_body_digest(&h, BODY).is_err());
    }

    #[test]
    fn rejects_a_missing_signature_header() {
        let d = http_signatures::sha256_digest(BODY);
        assert!(verify_body_digest(&headers(None, Some(&d)), BODY).is_err());
    }
}
