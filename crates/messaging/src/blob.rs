//! `GET /api/attachments/{id}/blob?token=<hmac>` — token-protected attachment
//! delivery.
//!
//! The metadata endpoint (`GET /api/attachments/{id}`) mints a short-lived
//! HMAC token bound to `(user_id, attachment_id, expires_at)`. The browser
//! follows the URL with that token; this handler validates it, then **streams
//! the bytes through the IdP**:
//!
//! - **Local attachments** (`remote_origin_url IS NULL`): GET the bytes from
//!   the local object store on the private network and stream them back.
//! - **Remote attachments**: HTTP-Signature fetch from the origin IdP, stream
//!   bytes back.
//!
//! In both cases the object store stays off the public network — the IdP's
//! HMAC token is the only authorization layer the browser interacts with.

use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{header, HeaderValue, StatusCode},
    response::Response,
};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use idp_db::models::Attachment;
use idp_db::repos::attachments;
use idp_state::{AppState, OidcError};

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Deserialize)]
pub struct BlobQuery {
    pub token: String,
}

/// Mint a token bound to (user, attachment, expires_at).
///
/// Format: `<user_uuid_simple>.<attachment_uuid_simple>.<expires_unix>.<mac_hex>`
/// The MAC is HMAC-SHA256 over the `<user>.<att>.<exp>` substring keyed by
/// `Config::session_secret`.
pub fn mint_blob_token(
    secret: &[u8],
    user_id: Uuid,
    attachment_id: Uuid,
    ttl: Duration,
) -> (String, SystemTime) {
    let now = SystemTime::now();
    let expires_at = now + ttl;
    let exp_unix = expires_at
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let payload = format!(
        "{}.{}.{}",
        user_id.simple(),
        attachment_id.simple(),
        exp_unix
    );
    let mac = compute_mac(secret, payload.as_bytes());
    let token = format!("{payload}.{}", encode_hex(&mac));
    (token, expires_at)
}

#[derive(Debug)]
pub enum TokenError {
    Malformed,
    InvalidSignature,
    Expired,
}

/// Verify a token against `secret`, returning `(user_id, attachment_id)` on success.
fn verify_blob_token(secret: &[u8], token: &str) -> Result<(Uuid, Uuid), TokenError> {
    // Split on the last '.' to separate payload from MAC.
    let (payload, mac_hex) = token.rsplit_once('.').ok_or(TokenError::Malformed)?;

    // Constant-time MAC verification.
    let mac_bytes = decode_hex(mac_hex).ok_or(TokenError::Malformed)?;
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(payload.as_bytes());
    mac.verify_slice(&mac_bytes)
        .map_err(|_| TokenError::InvalidSignature)?;

    // Parse the verified payload.
    let mut parts = payload.split('.');
    let user_id = parts
        .next()
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or(TokenError::Malformed)?;
    let attachment_id = parts
        .next()
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or(TokenError::Malformed)?;
    let exp_unix: u64 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or(TokenError::Malformed)?;
    if parts.next().is_some() {
        return Err(TokenError::Malformed);
    }

    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if now_unix > exp_unix {
        return Err(TokenError::Expired);
    }

    Ok((user_id, attachment_id))
}

/// `GET /api/attachments/{id}/blob?token=...`
///
/// Token auth (no Bearer). The path's `id` must match the token's
/// `attachment_id` — we don't trust the path alone, only the validated token.
#[tracing::instrument(skip_all, fields(id = %id))]
pub async fn get_attachment_blob(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Query(q): Query<BlobQuery>,
) -> Result<Response, OidcError> {
    let (_user_id, token_att_id) = match verify_blob_token(state.config.session_secret.as_bytes(), &q.token) {
        Ok(pair) => pair,
        Err(TokenError::Expired) => return Err(OidcError::access_denied("Token expired")),
        Err(_) => return Err(OidcError::access_denied("Invalid token")),
    };

    if token_att_id != id {
        return Err(OidcError::access_denied("Token does not match attachment"));
    }

    let attachment = attachments::find_by_id(&state.pool, id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::not_found("Attachment not found"))?;

    // Remote attachments: HTTP-Sig fetch from origin IdP, stream bytes back.
    if let Some(remote_url) = attachment.remote_origin_url.clone() {
        return fetch_remote_and_stream(&state, &remote_url, &attachment).await;
    }

    // Local: pull bytes off the object store on the private network and
    // stream them through us. The browser never talks to RustFS directly.
    let storage = state
        .storage
        .as_ref()
        .ok_or_else(|| OidcError::server_error("Object storage not configured"))?;

    let (stream, content_length) = storage
        .fetch_attachment_stream(&attachment.storage_key)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    let disposition = format!(
        r#"attachment; filename="{}""#,
        attachment.original_filename.replace('"', "")
    );

    let body = Body::from_stream(stream);
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, &attachment.mime_type)
        .header(header::CONTENT_DISPOSITION, &disposition)
        .header("x-content-type-options", "nosniff");
    if let Some(len) = content_length.filter(|n| *n >= 0) {
        builder = builder.header(header::CONTENT_LENGTH, len.to_string());
    }
    builder
        .body(body)
        .map_err(|e| OidcError::server_error(e.to_string()))
}

/// Fetch a remote attachment via HTTP-Signature auth and stream the bytes
/// back through us. The reqwest client follows the origin's `302` to its own
/// RustFS internally, so the only URL the browser sees is on this IdP.
async fn fetch_remote_and_stream(
    state: &AppState,
    remote_url: &str,
    attachment: &Attachment,
) -> Result<Response, OidcError> {
    let parsed = reqwest::Url::parse(remote_url)
        .map_err(|e| OidcError::server_error(format!("invalid remote_origin_url: {e}")))?;

    let host = parsed
        .host_str()
        .ok_or_else(|| OidcError::server_error("remote_origin_url has no host"))?;
    let host_with_port = match parsed.port() {
        Some(p) => format!("{host}:{p}"),
        None => host.to_string(),
    };
    let path_for_sig = match parsed.query() {
        Some(q) => format!("{}?{}", parsed.path(), q),
        None => parsed.path().to_string(),
    };

    let date = http_signatures::http_date_now();
    let key_id = format!("{}/actor#main-key", state.config.issuer());
    let signature = http_signatures::sign_request(http_signatures::SignParams {
        method: "get",
        path: &path_for_sig,
        host: &host_with_port,
        date: &date,
        digest: None,
        key_id: &key_id,
        signing_key: &state.keypair.signing_key,
    })
    .map_err(|e| OidcError::server_error(format!("failed to sign request: {e}")))?;

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    let response = client
        .get(remote_url)
        .header("Host", &host_with_port)
        .header("Date", &date)
        .header("Signature", &signature)
        .send()
        .await
        .map_err(|e| OidcError::server_error(format!("remote fetch failed: {e}")))?;

    if !response.status().is_success() {
        return Err(OidcError::server_error(format!(
            "remote IdP returned HTTP {} for attachment {}",
            response.status(),
            attachment.id
        )));
    }

    let disposition = format!(
        r#"attachment; filename="{}""#,
        attachment.original_filename.replace('"', "")
    );

    let body = Body::from_stream(response.bytes_stream());
    let mut out = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, &attachment.mime_type)
        .header(header::CONTENT_DISPOSITION, disposition)
        .body(body)
        .map_err(|e| OidcError::server_error(e.to_string()))?;
    out.headers_mut().insert(
        header::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    Ok(out)
}

/// Helper used by `get_attachment` (the metadata endpoint) to mint the URL it
/// returns to the client. Lives here so callers don't have to know the URL
/// shape.
pub fn build_blob_url(issuer: &str, attachment_id: Uuid, token: &str) -> String {
    format!("{issuer}/api/attachments/{attachment_id}/blob?token={token}")
}

// ── Hex helpers ──────────────────────────────────────────────────────────────
// Trivial inline implementations to avoid pulling in the `hex` crate for two functions.

fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = hex_nibble(bytes[i])?;
        let lo = hex_nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn compute_mac(secret: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}
