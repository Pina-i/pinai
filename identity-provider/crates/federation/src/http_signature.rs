//! Inter-IdP HTTP Signature verification.
//!
//! Used by every server-to-server endpoint that needs to authenticate the
//! requesting peer IdP — currently `/api/presence/batch`, `/api/presence/stream`,
//! and `/api/attachments/{id}/content`.
//!
//! Returns the verified `keyId` (e.g. `https://idp.alice.com/actor#main-key`)
//! on success, which callers can use to derive the requesting peer's actor URI.

use axum::http::HeaderMap;

use idp_state::OidcError;

/// Verify an incoming HTTP Signature by fetching the signer's public key from
/// their actor document at the URL embedded in `keyId`.
pub async fn verify_http_signature(
    headers: &HeaderMap,
    method: &str,
    path: &str,
) -> Result<String, OidcError> {
    let sig_header = headers
        .get("signature")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| OidcError::invalid_request("missing Signature header"))?;

    let parsed = http_signatures::parse_signature_header(sig_header)
        .map_err(|e| OidcError::invalid_request(format!("invalid Signature header: {e}")))?;

    let key_id = &parsed.key_id;
    let actor_url = key_id
        .split('#')
        .next()
        .ok_or_else(|| OidcError::invalid_request("invalid keyId format"))?;

    let client = reqwest::Client::new();
    let actor_doc: serde_json::Value = client
        .get(actor_url)
        .header("Accept", "application/activity+json")
        .send()
        .await
        .map_err(|e| OidcError::server_error(format!("failed to fetch actor: {e}")))?
        .json()
        .await
        .map_err(|e| OidcError::server_error(format!("failed to parse actor: {e}")))?;

    let public_key_pem = actor_doc
        .get("publicKey")
        .and_then(|pk| pk.get("publicKeyPem"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| OidcError::invalid_request("actor has no publicKeyPem"))?;

    let get_header = |name: &str| -> Option<String> {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    };

    http_signatures::verify_request(method, path, sig_header, get_header, public_key_pem)
        .map_err(|e| OidcError::access_denied(format!("signature verification failed: {e}")))?;

    Ok(key_id.to_string())
}

/// Verify the `Digest` header covers, and matches, the received body.
///
/// [`http_signatures::verify_request`] rebuilds the signing string from header
/// *values*, so a valid signature proves the sender signed some `Digest` value —
/// never that the body which arrived hashes to it. Both checks below are needed:
/// without the coverage check an attacker appends their own `Digest`, and
/// without the comparison a captured request is replayed with a swapped body.
pub fn verify_body_digest(headers: &HeaderMap, body: &[u8]) -> Result<(), OidcError> {
    let sig_header = headers
        .get("signature")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| OidcError::invalid_request("missing Signature header"))?;

    let parsed = http_signatures::parse_signature_header(sig_header)
        .map_err(|e| OidcError::invalid_request(format!("invalid Signature header: {e}")))?;

    if !parsed
        .headers
        .iter()
        .any(|h| h.eq_ignore_ascii_case("digest"))
    {
        return Err(OidcError::access_denied(
            "signature does not cover the Digest header",
        ));
    }

    let received = headers
        .get("digest")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| OidcError::invalid_request("missing Digest header"))?;

    if received != http_signatures::sha256_digest(body) {
        return Err(OidcError::access_denied(
            "Digest does not match request body",
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

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

    #[test]
    fn accepts_a_digest_that_covers_and_matches_the_body() {
        let d = http_signatures::sha256_digest(BODY);
        let h = headers(
            Some(&sig_header("(request-target) host date digest")),
            Some(&d),
        );
        assert!(verify_body_digest(&h, BODY).is_ok());
    }

    /// Replay with a swapped body: the signature is untouched and still covers
    /// `digest`, but the bytes that arrived no longer hash to it.
    #[test]
    fn rejects_a_body_that_does_not_match_the_digest() {
        let d = http_signatures::sha256_digest(BODY);
        let h = headers(
            Some(&sig_header("(request-target) host date digest")),
            Some(&d),
        );
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
        let h = headers(Some(&sig_header("(request-target) host date digest")), None);
        assert!(verify_body_digest(&h, BODY).is_err());
    }

    #[test]
    fn rejects_a_missing_signature_header() {
        let d = http_signatures::sha256_digest(BODY);
        assert!(verify_body_digest(&headers(None, Some(&d)), BODY).is_err());
    }
}
