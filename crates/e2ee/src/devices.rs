//! Per-device metadata for the Settings → Devices view (Phase 6b).
//!
//! Holds the User-Agent parser and the two device-management
//! endpoints (`GET /api/keys/devices`, `POST /api/keys/devices/:id/revoke`).
//! The KP-publish handler in `crates/e2ee/src/packages.rs` calls into
//! `parse_user_agent` + `user_devices::upsert_device` so a row is
//! materialised on the first KeyPackage publish per device.

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use base64ct::{Base64, Encoding as _};
use serde::{Deserialize, Serialize};
use time::{format_description::well_known::Rfc3339, Duration, OffsetDateTime};
use tracing::{info, instrument, warn};
use uuid::Uuid;

use idp_db::repos::{user_devices, users};
use idp_federation::auth::require_auth;
use idp_state::{AppState, OidcError};

use crate::attestation::{canonical_attestation_bytes, sign_attestation};

/// Phase 7 — IdP-attested DRK lifetime. Renews silently at 30-day window.
const ATTESTATION_TTL_DAYS: i64 = 365;

#[derive(Debug, Serialize)]
pub struct DeviceListEntry {
    pub device_id: Uuid,
    pub display_name: String,
    pub kind: String,
    #[serde(with = "time::serde::rfc3339")]
    pub paired_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last_seen_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub revoked_at: Option<OffsetDateTime>,
    /// Phase 7 — when the IdP-signed DRK attestation expires. None for rows
    /// that haven't yet completed `POST /api/keys/devices` registration.
    #[serde(with = "time::serde::rfc3339::option")]
    pub attestation_expires_at: Option<OffsetDateTime>,
}

/// `POST /api/keys/devices` request body — Phase 7.
#[derive(Debug, Deserialize)]
pub struct RegisterDeviceRequest {
    pub device_id: Uuid,
    /// Standard-base64-encoded Ed25519 public key (32 bytes raw).
    pub drk_public_key: String,
}

#[derive(Debug, Serialize)]
pub struct RegisterDeviceResponse {
    /// Standard-base64-encoded Ed25519 signature (64 bytes raw).
    pub signature: String,
    /// IdP JWKS `kid` of the signing key, for verification.
    pub kid: String,
    pub issued_at: String,    // RFC3339
    pub expires_at: String,   // RFC3339
    /// Standard-base64-encoded canonical bytes the IdP signed — returned so the
    /// client can re-verify locally before persisting.
    pub signed_message: String,
}

#[derive(Debug, Serialize)]
pub struct DeviceListResponse {
    pub devices: Vec<DeviceListEntry>,
}

/// `GET /api/keys/devices` (Bearer)
///
/// Enumerates every device row for the caller, active first then
/// revoked, each bucket ordered by `last_seen_at DESC`. The
/// `is_current` discrimination happens client-side — the server
/// doesn't know which `device_id` made this request.
#[instrument(skip_all)]
pub async fn get_devices(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<DeviceListResponse>, OidcError> {
    let user_id = require_auth(&state, &headers).await?;
    let rows = user_devices::list_user_devices(&state.pool, user_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;
    let devices = rows
        .into_iter()
        .map(|r| DeviceListEntry {
            device_id: r.device_id,
            display_name: r.display_name,
            kind: r.kind,
            paired_at: r.paired_at,
            last_seen_at: r.last_seen_at,
            revoked_at: r.revoked_at,
            attestation_expires_at: r.attestation_expires_at,
        })
        .collect();
    Ok(Json(DeviceListResponse { devices }))
}

/// `POST /api/keys/devices` (Bearer) — Phase 7.
///
/// Idempotent on `(device_id, drk_public_key)`. Three modes:
/// - **First-time registration**: new row → mint attestation, emit `DeviceJoined`.
/// - **Renewal**: same row + same DRK → re-mint with fresh `expires_at`.
/// - **Rotation**: same row + different DRK → overwrite DRK, log WARN. The
///   client must re-publish KeyPackages — any in-flight KPs signed by the
///   old DRK will fail leaf-signature validation on subsequent uploads.
///
/// Response carries the canonical bytes the IdP signed so the client can
/// re-verify locally before persisting.
#[instrument(skip_all, fields(device_id = %body.device_id))]
pub async fn register_device(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<RegisterDeviceRequest>,
) -> Result<(StatusCode, Json<RegisterDeviceResponse>), OidcError> {
    let user_id = require_auth(&state, &headers).await?;

    let drk_pub = Base64::decode_vec(&body.drk_public_key)
        .map_err(|_| OidcError::invalid_request("drk_public_key must be base64"))?;
    if drk_pub.len() != 32 {
        return Err(OidcError::invalid_request("drk_public_key must be 32 bytes (Ed25519)"));
    }

    let user = users::find_by_id(&state.pool, user_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::server_error("authenticated user vanished"))?;
    let actor_uri = user
        .actor_uri
        .clone()
        .ok_or_else(|| OidcError::server_error("user has no actor_uri"))?;

    // Look up the existing device row (created by Phase 6b's KP-publish hook,
    // or absent for a brand-new device that hasn't published yet).
    let existing = user_devices::find_with_attestation(&state.pool, body.device_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    let is_first_time = existing.as_ref().map(|d| d.drk_public_key.is_none()).unwrap_or(true);
    let is_rotation = match &existing {
        Some(d) => d
            .drk_public_key
            .as_deref()
            .map(|p| p != drk_pub.as_slice())
            .unwrap_or(false),
        None => false,
    };

    // Materialise the user_devices row when the device hits this endpoint
    // before its first KeyPackage publish (Phase 6b's KP hook usually creates
    // it on first publish, but Phase 7's flow may register before publishing).
    if existing.is_none() {
        user_devices::upsert_device(
            &state.pool,
            user_id,
            body.device_id,
            "Web client",
            "unknown",
        )
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;
    }

    if is_rotation {
        warn!(
            actor = %actor_uri,
            device = %body.device_id,
            "DRK rotation — in-flight KeyPackages signed by the old DRK become invalid",
        );
    }

    let issued_at = OffsetDateTime::now_utc();
    let expires_at = issued_at + Duration::days(ATTESTATION_TTL_DAYS);
    let kid = state.config.jwt_key_id.clone();

    let canonical = canonical_attestation_bytes(&actor_uri, &body.device_id, &drk_pub, expires_at, &kid);
    let signature = sign_attestation(&state.keypair.signing_key, &canonical);
    let sig_bytes: [u8; 64] = signature.to_bytes();

    user_devices::set_attestation(
        &state.pool,
        body.device_id,
        &drk_pub,
        &sig_bytes,
        &kid,
        issued_at,
        expires_at,
    )
    .await
    .map_err(|e| OidcError::server_error(e.to_string()))?;

    if is_first_time {
        info!(actor = %actor_uri, device = %body.device_id, "first-time device attestation minted");
        // WS DeviceJoined emit — implemented in Task 1.9.
        emit_device_joined(&state, &actor_uri, body.device_id, &drk_pub).await;
    }

    Ok((
        StatusCode::CREATED,
        Json(RegisterDeviceResponse {
            signature: Base64::encode_string(&sig_bytes),
            kid,
            issued_at: issued_at
                .format(&Rfc3339)
                .expect("RFC3339 format never fails"),
            expires_at: expires_at
                .format(&Rfc3339)
                .expect("RFC3339 format never fails"),
            signed_message: Base64::encode_string(&canonical),
        }),
    ))
}

/// Stub — Task 1.9 replaces this with a real WS hub broadcast.
async fn emit_device_joined(
    _state: &AppState,
    _actor_uri: &str,
    _device_id: Uuid,
    _drk_pub: &[u8],
) {
    // Intentional no-op until Task 1.9 wires the DeviceJoined WsServerEvent.
}

/// `POST /api/keys/devices/:device_id/revoke` (Bearer)
///
/// Marks the row revoked. Idempotent — calling twice is a no-op.
/// Returns 404 only when the `device_id` doesn't belong to the
/// caller (prevents cross-user revocation). The MLS Remove commits
/// that actually exclude this leaf from conversations are issued
/// client-side via `IE2eePort.revokeDevice`; this endpoint only
/// records the directory-level revocation flag.
#[instrument(skip_all, fields(device_id = %device_id))]
pub async fn revoke_device(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(device_id): Path<Uuid>,
) -> Result<StatusCode, OidcError> {
    let user_id = require_auth(&state, &headers).await?;

    // Disambiguate "already revoked" (200/204, idempotent) from "not
    // yours" (404). `mark_revoked` returns 0 rows in both cases; we
    // probe `exists` to decide.
    let touched = user_devices::mark_revoked(&state.pool, user_id, device_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;
    if touched == 0 {
        let exists = user_devices::exists(&state.pool, user_id, device_id)
            .await
            .map_err(|e| OidcError::server_error(e.to_string()))?;
        if !exists {
            return Err(OidcError::not_found("Device not found"));
        }
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Classifies a User-Agent header into `(display_name, kind)`.
///
/// `kind` is one of `"laptop" | "phone" | "tablet" | "unknown"` —
/// matches the schema CHECK constraint. The buckets are deliberately
/// coarse: we only need enough resolution to render a representative
/// icon + a one-line "Chrome on macOS" label in the device list.
/// Unrecognised UAs fall back to `("Web client", "unknown")` so the
/// row still renders.
///
/// Pure: no allocations beyond the returned `String`. Substring
/// matching keeps us off the third-party `woothee` / `uap-rust`
/// dependency tree.
pub fn parse_user_agent(ua: Option<&str>) -> (String, &'static str) {
    let Some(ua) = ua.filter(|s| !s.is_empty()) else {
        return ("Web client".to_string(), "unknown");
    };

    // iOS / iPadOS — checked first because they include "Safari" too.
    // iPad's UA can claim to be desktop Safari on iPadOS 13+; the
    // "iPad" substring still appears in most browsers' UA, but on
    // recent Safari it's gone. We accept that the iPad → desktop UA
    // case falls through to "laptop"; the icon will look wrong but
    // the row is still useful.
    if ua.contains("iPhone") {
        return (browser_on(ua, "iOS"), "phone");
    }
    if ua.contains("iPad") {
        return (browser_on(ua, "iPadOS"), "tablet");
    }

    // Android — phone vs tablet is communicated by the presence of
    // "Mobile" in the UA (per Google's guidance). Without it, Android
    // is a tablet.
    if ua.contains("Android") {
        let kind = if ua.contains("Mobile") { "phone" } else { "tablet" };
        return (browser_on(ua, "Android"), kind);
    }

    // Desktop browsers. Order matters: Edge / Opera identify as
    // Chromium too, so check the more-specific ones first.
    let os = detect_desktop_os(ua);
    if ua.contains("Edg/") || ua.contains("Edge/") {
        return (format!("Edge on {os}"), "laptop");
    }
    if ua.contains("OPR/") || ua.contains("Opera/") {
        return (format!("Opera on {os}"), "laptop");
    }
    if ua.contains("Firefox/") {
        return (format!("Firefox on {os}"), "laptop");
    }
    if ua.contains("Chrome/") {
        return (format!("Chrome on {os}"), "laptop");
    }
    if ua.contains("Safari/") {
        return (format!("Safari on {os}"), "laptop");
    }

    ("Web client".to_string(), "unknown")
}

fn detect_desktop_os(ua: &str) -> &'static str {
    if ua.contains("Mac OS X") || ua.contains("macOS") {
        "macOS"
    } else if ua.contains("Windows") {
        "Windows"
    } else if ua.contains("Linux") {
        "Linux"
    } else {
        "this device"
    }
}

fn browser_on(ua: &str, os: &str) -> String {
    let browser = if ua.contains("CriOS/") {
        "Chrome"
    } else if ua.contains("FxiOS/") {
        "Firefox"
    } else if ua.contains("EdgiOS/") {
        "Edge"
    } else if ua.contains("Firefox/") {
        "Firefox"
    } else if ua.contains("Chrome/") {
        "Chrome"
    } else if ua.contains("Safari/") {
        "Safari"
    } else {
        "Browser"
    };
    format!("{browser} on {os}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_ua_falls_back_to_web_client() {
        assert_eq!(parse_user_agent(None), ("Web client".to_string(), "unknown"));
        assert_eq!(parse_user_agent(Some("")), ("Web client".to_string(), "unknown"));
    }

    #[test]
    fn iphone_safari() {
        let ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) \
                  AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1";
        assert_eq!(parse_user_agent(Some(ua)), ("Safari on iOS".to_string(), "phone"));
    }

    #[test]
    fn ipad_safari() {
        let ua = "Mozilla/5.0 (iPad; CPU OS 17_3 like Mac OS X) \
                  AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1";
        assert_eq!(parse_user_agent(Some(ua)), ("Safari on iPadOS".to_string(), "tablet"));
    }

    #[test]
    fn android_chrome_phone() {
        let ua = "Mozilla/5.0 (Linux; Android 14; Pixel 8) \
                  AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36";
        assert_eq!(parse_user_agent(Some(ua)), ("Chrome on Android".to_string(), "phone"));
    }

    #[test]
    fn android_chrome_tablet() {
        // Same UA without "Mobile" → tablet per Google's convention.
        let ua = "Mozilla/5.0 (Linux; Android 14) \
                  AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36";
        assert_eq!(parse_user_agent(Some(ua)), ("Chrome on Android".to_string(), "tablet"));
    }

    #[test]
    fn firefox_macos() {
        let ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:130.0) Gecko/20100101 Firefox/130.0";
        assert_eq!(parse_user_agent(Some(ua)), ("Firefox on macOS".to_string(), "laptop"));
    }

    #[test]
    fn chrome_windows() {
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
                  AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36";
        assert_eq!(parse_user_agent(Some(ua)), ("Chrome on Windows".to_string(), "laptop"));
    }

    #[test]
    fn edge_wins_over_chrome() {
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
                  AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0";
        assert_eq!(parse_user_agent(Some(ua)), ("Edge on Windows".to_string(), "laptop"));
    }

    #[test]
    fn unrecognised_ua() {
        assert_eq!(
            parse_user_agent(Some("WeirdCustomBot/1.0")),
            ("Web client".to_string(), "unknown"),
        );
    }
}
