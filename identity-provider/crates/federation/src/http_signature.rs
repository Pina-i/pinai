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
