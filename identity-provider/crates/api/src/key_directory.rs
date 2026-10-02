//! Devices and KeyPackages — see identity-provider/specs/e2ee.md § 5.

use std::sync::Arc;

use application::e2ee::{
    ClaimKeyPackage, KeyPackageStatus, ListDevices, RegisterDevice, RevokeDevice, UploadKeyPackages,
};
use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use domain::e2ee::{
    Claim, Device, DeviceLabel, DeviceRootKey, KeyDirectoryError, KeyPackageBytes, NewKeyPackage,
};
use domain::identity::{ActorUri, Requester};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use crate::ApiError;
use crate::auth::{Authenticated, CallerJson};
use crate::rate_limit::RateLimiter;

#[derive(Serialize)]
pub struct DeviceEntry {
    device_id: Uuid,
    display_name: String,
    kind: &'static str,
    #[serde(with = "time::serde::rfc3339")]
    paired_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    last_seen_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    revoked_at: Option<OffsetDateTime>,
    /// `None` until the device registers its root key.
    #[serde(with = "time::serde::rfc3339::option")]
    attestation_expires_at: Option<OffsetDateTime>,
}

#[derive(Serialize)]
pub struct DevicesBody {
    devices: Vec<DeviceEntry>,
}

#[derive(Deserialize)]
pub struct RegisterRequest {
    device_id: Uuid,
    /// Standard base64 of the 32-byte Ed25519 public key.
    drk_public_key: String,
}

#[derive(Serialize)]
pub struct RegisteredBody {
    signature: String,
    kid: String,
    issued_at: String,
    expires_at: String,
    /// The bytes signed, so the client verifies them before trusting them.
    signed_message: String,
}

#[derive(Deserialize)]
pub struct UploadRequest {
    device_id: Uuid,
    packages: Vec<UploadEntry>,
}

#[derive(Deserialize)]
pub struct UploadEntry {
    key_package: String,
    #[serde(with = "time::serde::rfc3339")]
    expires_at: OffsetDateTime,
}

#[derive(Serialize)]
pub struct UploadedBody {
    uploaded: usize,
    available_after: usize,
}

#[derive(Deserialize)]
pub struct ClaimRequest {
    actor_uri: String,
    /// Omitted, any device of the account's with KeyPackages left.
    #[serde(default)]
    device_id: Option<Uuid>,
}

#[derive(Deserialize)]
pub struct ClaimEachRequest {
    actor_uri: String,
}

#[derive(Serialize)]
pub struct ClaimsBody {
    claims: Vec<ClaimedBody>,
}

#[derive(Serialize)]
pub struct ClaimedBody {
    key_package: String,
    /// The device claimed from: the Welcome targets it.
    device_id: Uuid,
    #[serde(with = "time::serde::rfc3339")]
    expires_at: OffsetDateTime,
    remaining_count: usize,
    needs_refill: bool,
}

#[derive(Serialize)]
pub struct DeviceStashBody {
    device_id: Uuid,
    available: usize,
    needs_refill: bool,
}

#[derive(Serialize)]
pub struct StatusBody {
    devices: Vec<DeviceStashBody>,
    refill_threshold: usize,
    cap: usize,
}

impl From<Device> for DeviceEntry {
    fn from(device: Device) -> Self {
        Self {
            device_id: device.id.as_uuid(),
            display_name: device.label.name,
            kind: device.label.kind.as_str(),
            paired_at: device.paired_at,
            last_seen_at: device.last_seen_at,
            revoked_at: device.revoked_at,
            attestation_expires_at: device.attestation.map(|a| a.expires_at),
        }
    }
}

fn rfc3339(at: OffsetDateTime) -> Result<String, ApiError> {
    at.format(&Rfc3339)
        .map_err(|e| ApiError::internal(anyhow::Error::from(e)))
}

/// `GET /api/keys/devices`
pub async fn devices(
    State(list): State<Arc<ListDevices>>,
    Authenticated(user): Authenticated,
) -> Result<Json<DevicesBody>, ApiError> {
    let devices = list.execute(user).await?;
    Ok(Json(DevicesBody {
        devices: devices.into_iter().map(DeviceEntry::from).collect(),
    }))
}

/// `POST /api/keys/devices`
pub async fn register(
    State(register): State<Arc<RegisterDevice>>,
    Authenticated(user): Authenticated,
    Json(body): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<RegisteredBody>), ApiError> {
    let key = B64
        .decode(&body.drk_public_key)
        .map_err(|_| ApiError::bad_request("drk_public_key must be base64"))?;
    let key = DeviceRootKey::parse(&key)
        .map_err(|_| ApiError::bad_request("drk_public_key must be 32 bytes (Ed25519)"))?;
    let registered = register
        .execute(user, body.device_id.into(), key, OffsetDateTime::now_utc())
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(RegisteredBody {
            signature: B64.encode(&registered.signed.signature),
            kid: registered.signed.kid,
            issued_at: rfc3339(registered.issued_at)?,
            expires_at: rfc3339(registered.expires_at)?,
            signed_message: B64.encode(&registered.signed.signed_message),
        }),
    ))
}

/// `POST /api/keys/devices/{device_id}/revoke`
pub async fn revoke(
    State(revoke): State<Arc<RevokeDevice>>,
    Authenticated(user): Authenticated,
    Path(device_id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    revoke.execute(user, device_id.into()).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /api/keys/packages`
pub async fn upload(
    State(upload): State<Arc<UploadKeyPackages>>,
    Authenticated(user): Authenticated,
    headers: HeaderMap,
    Json(body): Json<UploadRequest>,
) -> Result<(StatusCode, Json<UploadedBody>), ApiError> {
    let packages = body
        .packages
        .into_iter()
        .enumerate()
        .map(|(i, entry)| {
            let bytes = B64.decode(&entry.key_package).map_err(|_| {
                ApiError::bad_request(format!("packages[{i}].key_package is not valid base64"))
            })?;
            let bytes = KeyPackageBytes::parse(bytes).map_err(|_| {
                ApiError::bad_request(format!("packages[{i}].key_package is empty"))
            })?;
            Ok(NewKeyPackage {
                bytes,
                expires_at: entry.expires_at,
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    let label = DeviceLabel::from_user_agent(
        headers
            .get(header::USER_AGENT)
            .and_then(|value| value.to_str().ok()),
    );
    let uploaded = upload
        .execute(
            user,
            body.device_id.into(),
            label,
            packages,
            OffsetDateTime::now_utc(),
        )
        .await?;
    tracing::info!(user_id = %user, device_id = %body.device_id, added = uploaded.uploaded, available_after = uploaded.available_after, "key packages uploaded");
    Ok((
        StatusCode::CREATED,
        Json(UploadedBody {
            uploaded: uploaded.uploaded,
            available_after: uploaded.available_after,
        }),
    ))
}

/// `POST /api/keys/packages/claim` — by a local user, or by a peer instance for an account of
/// this one.
pub async fn claim(
    State(claim): State<Arc<ClaimKeyPackage>>,
    State(limiter): State<Arc<RateLimiter>>,
    CallerJson(requester, body): CallerJson<ClaimRequest>,
) -> Result<Json<ClaimedBody>, ApiError> {
    let bucket = match &requester {
        Requester::User(user) => format!("user:{user}"),
        Requester::Peer(peer) => format!("peer:{peer}"),
    };
    if !limiter.allow(&bucket) {
        tracing::warn!(%bucket, "rate-limited claim request");
        return Err(rate_limited());
    }
    let target = ActorUri::parse(&body.actor_uri)
        .map_err(|_| ApiError::bad_request("`actor_uri` is not a valid URL"))?;
    let claimed = claim
        .execute(&requester, &target, body.device_id.map(Into::into))
        .await?;
    Ok(Json(claimed.into()))
}

/// `POST /api/keys/packages/claim/devices` — one package of each of the account's devices, by a
/// local user or a peer instance, limited as a claim is.
pub async fn claim_each_device(
    State(claim): State<Arc<ClaimKeyPackage>>,
    State(limiter): State<Arc<RateLimiter>>,
    CallerJson(requester, body): CallerJson<ClaimEachRequest>,
) -> Result<Json<ClaimsBody>, ApiError> {
    let bucket = match &requester {
        Requester::User(user) => format!("user:{user}"),
        Requester::Peer(peer) => format!("peer:{peer}"),
    };
    if !limiter.allow(&bucket) {
        tracing::warn!(%bucket, "rate-limited claim request");
        return Err(rate_limited());
    }
    let target = ActorUri::parse(&body.actor_uri)
        .map_err(|_| ApiError::bad_request("`actor_uri` is not a valid URL"))?;
    let claims = claim.each_device(&requester, &target).await?;
    Ok(Json(ClaimsBody {
        claims: claims.into_iter().map(Into::into).collect(),
    }))
}

impl From<Claim> for ClaimedBody {
    fn from(claimed: Claim) -> Self {
        Self {
            key_package: B64.encode(claimed.package.bytes.as_bytes()),
            device_id: claimed.package.device.as_uuid(),
            expires_at: claimed.package.expires_at,
            remaining_count: claimed.remaining,
            needs_refill: claimed.needs_refill,
        }
    }
}

/// `GET /api/keys/packages/status`
pub async fn status(
    State(status): State<Arc<KeyPackageStatus>>,
    Authenticated(user): Authenticated,
) -> Result<Json<StatusBody>, ApiError> {
    let stash = status.execute(user).await?;
    Ok(Json(StatusBody {
        devices: stash
            .devices
            .into_iter()
            .map(|d| DeviceStashBody {
                device_id: d.device.as_uuid(),
                available: d.available,
                needs_refill: d.needs_refill,
            })
            .collect(),
        refill_threshold: stash.refill_threshold,
        cap: stash.cap,
    }))
}

fn rate_limited() -> ApiError {
    ApiError::new(
        StatusCode::TOO_MANY_REQUESTS,
        "too_many_requests",
        "rate limit exceeded",
    )
}

impl From<KeyDirectoryError> for ApiError {
    fn from(error: KeyDirectoryError) -> Self {
        match error {
            KeyDirectoryError::Refused(refusal) => ApiError::bad_request(refusal.to_string()),
            KeyDirectoryError::DeviceNotFound => ApiError::not_found("Device not found"),
            KeyDirectoryError::DeviceTaken => {
                ApiError::new(StatusCode::CONFLICT, "conflict", "Device id already taken")
            }
            KeyDirectoryError::DeviceRevoked => {
                ApiError::new(StatusCode::FORBIDDEN, "access_denied", "Device is revoked")
            }
            KeyDirectoryError::UserNotFound => ApiError::not_found("User not found"),
            KeyDirectoryError::NoKeyPackage => {
                ApiError::new(StatusCode::CONFLICT, "conflict", "no available KeyPackage")
            }
            KeyDirectoryError::PeerMustTargetLocal => {
                ApiError::bad_request("peer-authenticated claim must target a local actor")
            }
            KeyDirectoryError::PeerNotAllowed(reason) => ApiError::bad_request(reason),
            KeyDirectoryError::PeerBusy => rate_limited(),
            KeyDirectoryError::PeerUnavailable(e) => ApiError::upstream(e),
            KeyDirectoryError::Unreachable => ApiError::new(
                StatusCode::FORBIDDEN,
                "access_denied",
                "Can't add this person",
            ),
            KeyDirectoryError::Unexpected(e) => ApiError::internal(e),
        }
    }
}

#[cfg(test)]
mod tests;
