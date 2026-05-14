//! KeyPackage stash endpoints.
//!
//! - `POST /api/keys/packages` (Bearer)         — upload a batch for a device.
//! - `POST /api/keys/packages/claim` (Bearer or HTTP-Sig) — atomic single-use claim.
//! - `GET  /api/keys/packages/status` (Bearer)   — per-device counts + refill flag.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tracing::{instrument, warn};
use uuid::Uuid;

use idp_db::repos::{key_packages, user_devices, users};
use idp_federation::auth::require_auth;
use idp_federation::delivery as federation_delivery;
use idp_state::{AppState, OidcError};

use crate::auth::{require_user_or_peer, Requester};
use crate::devices::parse_user_agent;
use crate::rate_limit::try_consume;

// ── POST /api/keys/packages ──────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct UploadPackagesRequest {
    pub device_id: Uuid,
    pub packages: Vec<UploadPackageEntry>,
}

#[derive(Debug, Deserialize)]
pub struct UploadPackageEntry {
    pub key_package: String,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
}

#[derive(Debug, Serialize)]
pub struct UploadPackagesResponse {
    pub uploaded: usize,
    pub available_after: i64,
}

#[instrument(skip_all, fields(device_id = %body.device_id, count = body.packages.len()))]
pub async fn post_packages(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<UploadPackagesRequest>,
) -> Result<(StatusCode, Json<UploadPackagesResponse>), OidcError> {
    let user_id = require_auth(&state, &headers).await?;

    if body.packages.is_empty() {
        return Err(OidcError::invalid_request("packages must be non-empty"));
    }

    // Lifetime check on every entry — server-imposed ceiling on `expires_at`.
    let now = OffsetDateTime::now_utc();
    let max_lifetime = time::Duration::seconds(
        state.config.e2ee_keypackage_lifetime.as_secs() as i64,
    );
    for (i, entry) in body.packages.iter().enumerate() {
        let lifetime = entry.expires_at - now;
        if lifetime > max_lifetime {
            return Err(OidcError::invalid_request(format!(
                "packages[{i}].expires_at exceeds the maximum allowed lifetime"
            )));
        }
        if lifetime <= time::Duration::ZERO {
            return Err(OidcError::invalid_request(format!(
                "packages[{i}].expires_at is in the past"
            )));
        }
    }

    // Cap check: reject the whole batch if it would push us past the cap.
    let cap = state.config.e2ee_keypackage_cap_per_device as i64;
    let available = key_packages::count_available(&state.pool, user_id, body.device_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;
    let proposed = available + body.packages.len() as i64;
    if proposed > cap {
        return Err(OidcError::invalid_request(format!(
            "stash cap exceeded: have {available}, uploading {}, cap is {cap}",
            body.packages.len()
        )));
    }

    // Decode all blobs up front so a malformed entry doesn't leave a partial
    // batch in the table.
    let mut decoded: Vec<Vec<u8>> = Vec::with_capacity(body.packages.len());
    for (i, entry) in body.packages.iter().enumerate() {
        let bytes = B64
            .decode(&entry.key_package)
            .map_err(|_| OidcError::invalid_request(format!("packages[{i}].key_package is not valid base64")))?;
        if bytes.is_empty() {
            return Err(OidcError::invalid_request(format!(
                "packages[{i}].key_package is empty"
            )));
        }
        decoded.push(bytes);
    }

    let pending: Vec<key_packages::PendingPackage<'_>> = decoded
        .iter()
        .zip(body.packages.iter())
        .map(|(bytes, entry)| key_packages::PendingPackage {
            key_package: bytes.as_slice(),
            expires_at: entry.expires_at,
        })
        .collect();

    let inserted = key_packages::insert_batch(&state.pool, user_id, body.device_id, &pending)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    // Phase 6b: materialise the device row for the Settings → Devices
    // view. `upsert_device` inserts on first publish (using the UA-
    // derived name + kind) and just bumps `last_seen_at` on every
    // subsequent call. Failures here are non-fatal — the KeyPackages
    // are already stored; the user can't see this row in the UI but
    // every functional path still works.
    let ua = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok());
    let (display_name, kind) = parse_user_agent(ua);
    if let Err(e) =
        user_devices::upsert_device(&state.pool, user_id, body.device_id, &display_name, kind)
            .await
    {
        warn!(
            user_id = %user_id,
            device_id = %body.device_id,
            "user_devices upsert failed (non-fatal): {e}"
        );
    }

    let available_after = available + inserted.len() as i64;
    tracing::info!(
        user_id = %user_id,
        device_id = %body.device_id,
        added = inserted.len(),
        available_after,
        "key packages uploaded"
    );

    Ok((
        StatusCode::CREATED,
        Json(UploadPackagesResponse {
            uploaded: inserted.len(),
            available_after,
        }),
    ))
}

// ── POST /api/keys/packages/claim ────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ClaimRequest {
    pub actor_uri: String,
    /// Optional after Phase 5b: when omitted, server picks any device
    /// of `actor_uri` that has spare KeyPackages. Cross-IdP callers
    /// don't know the target user's device IDs, so they leave this
    /// out; same-user multi-device flows can still pin a specific
    /// device.
    #[serde(default)]
    pub device_id: Option<Uuid>,
}

#[derive(Debug, Serialize)]
pub struct ClaimResponse {
    pub key_package: String,
    /// The device the server actually claimed from — needed by the
    /// caller so the resulting Welcome can target the right leaf.
    pub device_id: Uuid,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    pub remaining_count: i64,
    pub needs_refill: bool,
}

#[instrument(skip_all, fields(actor_uri = %body.actor_uri, device_id = ?body.device_id))]
pub async fn post_packages_claim(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ClaimRequest>,
) -> Result<Json<ClaimResponse>, OidcError> {
    let requester = require_user_or_peer(&state, &headers, "post", "/api/keys/packages/claim").await?;

    // Rate-limit per requester identity to bound abuse.
    if !try_consume(&requester.rate_limit_key()) {
        warn!(key = %requester.rate_limit_key(), "rate-limited claim request");
        return Err(OidcError::access_denied("rate limit exceeded"));
    }

    // Local-vs-remote dispatch.
    //
    // - Bearer (local user) + remote target → proxy via HTTP-Sig to
    //   the target's IdP. The browser can't sign HTTP-Sig itself
    //   (the IdP key is server-side), so this proxy hop is required.
    // - Peer (HTTP-Sig) + remote target → reject. Peers shouldn't
    //   chain proxies through us; they should hit the target IdP
    //   directly.
    // - Either auth + local target → existing local lookup.
    let local_prefix = format!("{}/users/", state.config.issuer());
    let is_local = body.actor_uri.starts_with(&local_prefix);

    if !is_local {
        match &requester {
            Requester::User(user_id) => {
                return proxy_claim_to_remote(&state, &body, *user_id).await;
            }
            Requester::Peer(_) => {
                return Err(OidcError::invalid_request(
                    "peer-authenticated claim must target a local actor",
                ));
            }
        }
    }

    let user = users::find_by_actor_uri(&state.pool, &body.actor_uri)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::not_found("User not found"))?;

    let claimed = match body.device_id {
        Some(device_id) => key_packages::claim_one(&state.pool, user.id, device_id).await,
        None => key_packages::claim_one_any_device(&state.pool, user.id).await,
    }
    .map_err(|e| OidcError::server_error(e.to_string()))?
    .ok_or_else(|| OidcError::server_error("no available KeyPackage"))?;

    let remaining = key_packages::count_available(&state.pool, user.id, claimed.device_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    let threshold = state.config.e2ee_keypackage_refill_threshold as i64;
    let needs_refill = remaining <= threshold;

    Ok(Json(ClaimResponse {
        key_package: B64.encode(&claimed.key_package),
        device_id: claimed.device_id,
        expires_at: claimed.expires_at,
        remaining_count: remaining,
        needs_refill,
    }))
}

/// Phase 5d.1: federate the claim to the remote IdP that owns
/// `body.actor_uri`. The local user (resolved from their bearer
/// token) signs the outbound HTTP-Sig request via the IdP's keypair.
///
/// We parse the target URL straight out of the actor URI rather than
/// re-doing WebFinger — actor URIs are canonical
/// `<scheme>://<host>/users/<handle>` strings; the claim endpoint
/// lives at `<scheme>://<host>/api/keys/packages/claim`.
async fn proxy_claim_to_remote(
    state: &AppState,
    body: &ClaimRequest,
    sender_user_id: Uuid,
) -> Result<Json<ClaimResponse>, OidcError> {
    let sender = users::find_by_id(&state.pool, sender_user_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::server_error("authenticated user not found"))?;

    let parsed: url::Url = body
        .actor_uri
        .parse()
        .map_err(|_| OidcError::invalid_request("`actor_uri` is not a valid URL"))?;
    let scheme = parsed.scheme();
    let host = parsed
        .host_str()
        .ok_or_else(|| OidcError::invalid_request("`actor_uri` missing host"))?;
    let target_url = match parsed.port() {
        Some(p) => format!("{}://{}:{}/api/keys/packages/claim", scheme, host, p),
        None => format!("{}://{}/api/keys/packages/claim", scheme, host),
    };

    let outbound = serde_json::json!({
        "actor_uri": body.actor_uri,
        "device_id": body.device_id,
    });

    tracing::info!(
        target = %target_url,
        sender = %sender.username,
        "federating /api/keys/packages/claim to remote IdP"
    );

    let response: ClaimResponseDto =
        federation_delivery::signed_post_json(state, &target_url, &outbound, &sender.username)
            .await?;

    Ok(Json(ClaimResponse {
        key_package: response.key_package,
        device_id: response.device_id,
        expires_at: response.expires_at,
        remaining_count: response.remaining_count,
        needs_refill: response.needs_refill,
    }))
}

/// Wire-shape mirror of [`ClaimResponse`] for parsing the federated
/// peer's reply — same fields, but with `Deserialize` so the typed
/// HTTP-Sig helper can decode.
#[derive(Debug, Deserialize)]
struct ClaimResponseDto {
    key_package: String,
    device_id: Uuid,
    #[serde(with = "time::serde::rfc3339")]
    expires_at: OffsetDateTime,
    remaining_count: i64,
    needs_refill: bool,
}

// ── GET /api/keys/packages/status ────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct StatusResponse {
    pub devices: Vec<DeviceStatus>,
    pub refill_threshold: i64,
    pub cap: i64,
}

#[derive(Debug, Serialize)]
pub struct DeviceStatus {
    pub device_id: Uuid,
    pub available: i64,
    pub needs_refill: bool,
}

#[instrument(skip_all)]
pub async fn get_packages_status(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<StatusResponse>, OidcError> {
    let user_id = require_auth(&state, &headers).await?;

    let counts = key_packages::count_per_device(&state.pool, user_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    let threshold = state.config.e2ee_keypackage_refill_threshold as i64;
    let cap = state.config.e2ee_keypackage_cap_per_device as i64;

    let devices = counts
        .into_iter()
        .map(|(device_id, available)| DeviceStatus {
            device_id,
            available,
            needs_refill: available <= threshold,
        })
        .collect();

    Ok(Json(StatusResponse {
        devices,
        refill_threshold: threshold,
        cap,
    }))
}
