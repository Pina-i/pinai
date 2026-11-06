//! Devices and KeyPackages — see identity-provider/specs/e2ee.md § 5.

use std::sync::Arc;

use application::e2ee::{
    ClaimKeyPackage, KeyPackageStatus, ListDevices, ListedDevice, RegisterDevice, ReportHistoryKey,
    RevokeDevice, UploadKeyPackages,
};
use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use domain::e2ee::{
    Approval, Approver, Claim, DeviceLabel, DeviceRootKey, Ed25519Signature, HistoryGeneration,
    HpkePublicKey, KeyDirectoryError, KeyPackageBytes, NewKeyPackage, RequestRefusal,
    UnverifiedHpkeKey,
};
use domain::identity::{ActorUri, Requester};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use crate::ApiError;
use crate::auth::{Authenticated, CallerJson, RecentlySignedIn, SignedIn};
use crate::e2ee::{
    approval_required, base64_field, device_required, stale_history_key, start_over_refused,
};
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
    /// Signed in: a live session of it.
    signed_in: bool,
    /// That session's last use; `None` when signed out.
    #[serde(with = "time::serde::rfc3339::option")]
    last_active_at: Option<OffsetDateTime>,
    /// `None` until the device registers its root key.
    #[serde(with = "time::serde::rfc3339::option")]
    attestation_expires_at: Option<OffsetDateTime>,
    drk_public_key: Option<String>,
    attestation_signature: Option<String>,
    attestation_kid: Option<String>,
    hpke_public_key: Option<String>,
    hpke_key_signature: Option<String>,
    /// The history key's generation the device says it holds.
    history_generation: Option<i32>,
    /// Oldest first; each binds `drk_public_key`, which another device checks it over.
    approvals: Vec<ApprovalEntry>,
}

/// `{ by: "device", device_id }` or `{ by: "passphrase", generation }`, with the signature.
#[derive(Serialize)]
pub struct ApprovalEntry {
    by: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    generation: Option<i32>,
    signature: String,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
}

impl From<Approval> for ApprovalEntry {
    fn from(approval: Approval) -> Self {
        let (by, device_id, generation) = match approval.approver {
            Approver::Device(device) => ("device", Some(device.as_uuid()), None),
            Approver::Passphrase(generation) => ("passphrase", None, Some(generation.value())),
        };
        Self {
            by,
            device_id,
            generation,
            signature: B64.encode(approval.signature.as_bytes()),
            created_at: approval.created_at,
        }
    }
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
    /// Standard base64 of the 32-byte X25519 public key; sent with its signature, or neither is.
    hpke_public_key: Option<String>,
    /// Standard base64 of the root key's 64-byte signature over the HPKE key's canonical bytes.
    hpke_key_signature: Option<String>,
}

#[derive(Deserialize)]
pub struct HistoryKeyHeld {
    generation: i64,
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

impl From<ListedDevice> for DeviceEntry {
    fn from(
        ListedDevice {
            device,
            last_active_at,
            approvals,
        }: ListedDevice,
    ) -> Self {
        let attestation = device.attestation.as_ref();
        let hpke_key = device.hpke_key.as_ref();
        Self {
            device_id: device.id.as_uuid(),
            display_name: device.label.name,
            kind: device.label.kind.as_str(),
            paired_at: device.paired_at,
            last_seen_at: device.last_seen_at,
            revoked_at: device.revoked_at,
            signed_in: last_active_at.is_some(),
            last_active_at,
            attestation_expires_at: attestation.map(|a| a.expires_at),
            drk_public_key: attestation.map(|a| B64.encode(a.root_key.as_bytes())),
            attestation_signature: attestation.map(|a| B64.encode(&a.signature)),
            attestation_kid: attestation.map(|a| a.kid.clone()),
            hpke_public_key: hpke_key.map(|h| B64.encode(h.key.as_bytes())),
            hpke_key_signature: hpke_key.map(|h| B64.encode(h.signature.as_bytes())),
            history_generation: device.history_generation.map(HistoryGeneration::value),
            approvals: approvals.into_iter().map(ApprovalEntry::from).collect(),
        }
    }
}

fn user_agent_label(headers: &HeaderMap) -> DeviceLabel {
    DeviceLabel::from_user_agent(
        headers
            .get(header::USER_AGENT)
            .and_then(|value| value.to_str().ok()),
    )
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
    let devices = list.execute(user, OffsetDateTime::now_utc()).await?;
    Ok(Json(DevicesBody {
        devices: devices.into_iter().map(DeviceEntry::from).collect(),
    }))
}

/// `POST /api/keys/devices`
pub async fn register(
    State(register): State<Arc<RegisterDevice>>,
    SignedIn(bearer): SignedIn,
    headers: HeaderMap,
    Json(body): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<RegisteredBody>), ApiError> {
    let key = base64_field("drk_public_key", &body.drk_public_key, DeviceRootKey::parse)?;
    let hpke_public_key = body
        .hpke_public_key
        .as_deref()
        .map(|raw| base64_field("hpke_public_key", raw, HpkePublicKey::parse))
        .transpose()?;
    let hpke_key_signature = body
        .hpke_key_signature
        .as_deref()
        .map(|raw| {
            base64_field("hpke_key_signature", raw, |bytes| {
                Ed25519Signature::parse("hpke_key_signature", bytes)
            })
        })
        .transpose()?;
    let brought = UnverifiedHpkeKey::from_parts(hpke_public_key, hpke_key_signature)?;
    let registered = register
        .execute(
            &bearer,
            body.device_id.into(),
            key,
            brought,
            &user_agent_label(&headers),
            OffsetDateTime::now_utc(),
        )
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
    RecentlySignedIn(bearer): RecentlySignedIn,
    Path(device_id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    revoke
        .execute(&bearer, device_id.into(), OffsetDateTime::now_utc())
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `PUT /api/keys/devices/{device_id}/history-key`
pub async fn hold_history_key(
    State(report): State<Arc<ReportHistoryKey>>,
    SignedIn(bearer): SignedIn,
    Path(device_id): Path<Uuid>,
    Json(body): Json<HistoryKeyHeld>,
) -> Result<StatusCode, ApiError> {
    let generation = HistoryGeneration::parse(body.generation)?;
    report
        .execute(&bearer, device_id.into(), generation)
        .await?;
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
    let label = user_agent_label(&headers);
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

fn no_root_key() -> ApiError {
    ApiError::new(
        StatusCode::CONFLICT,
        "no_root_key",
        "The device has registered no root key",
    )
}

fn request_refused(refusal: RequestRefusal) -> ApiError {
    match refusal {
        RequestRefusal::NotFound => ApiError::not_found("Approval request not found"),
        RequestRefusal::Ended => ApiError::new(
            StatusCode::GONE,
            "approval_request_ended",
            "The approval request has ended",
        ),
        RequestRefusal::Taken => ApiError::new(
            StatusCode::CONFLICT,
            "approval_request_taken",
            "Another device is answering this approval request",
        ),
        RequestRefusal::Full => ApiError::new(
            StatusCode::CONFLICT,
            "approval_request_full",
            "The approval request holds no more messages",
        ),
        RequestRefusal::TooMany => ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too_many_requests",
            "Too many approval requests in the last hour",
        ),
        RequestRefusal::NoRootKey => no_root_key(),
    }
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
            KeyDirectoryError::HpkeKeyUnsigned => {
                ApiError::bad_request("hpke_key_signature does not verify against drk_public_key")
            }
            KeyDirectoryError::NotTheSessionsDevice => ApiError::new(
                StatusCode::FORBIDDEN,
                "device_mismatch",
                "This session signed in another device",
            ),
            KeyDirectoryError::NoRootKey => no_root_key(),
            KeyDirectoryError::SelfApproval => {
                ApiError::bad_request("A device approves itself with the passphrase only")
            }
            KeyDirectoryError::ApprovalUnsigned => {
                ApiError::bad_request("signature does not verify over the device's root key")
            }
            KeyDirectoryError::SelfShare => {
                ApiError::bad_request("A device shares the history key with another device")
            }
            KeyDirectoryError::NoHpkeKey => ApiError::new(
                StatusCode::CONFLICT,
                "no_hpke_key",
                "The device has registered no HPKE key",
            ),
            KeyDirectoryError::HistoryKeyNotHeld => ApiError::new(
                StatusCode::CONFLICT,
                "history_key_not_held",
                "This device hasn't said it holds the current history key",
            ),
            KeyDirectoryError::HistoryKeyHeld => ApiError::new(
                StatusCode::CONFLICT,
                "history_key_held",
                "The device holds the current history key already",
            ),
            KeyDirectoryError::SenderNotApproved => ApiError::new(
                StatusCode::CONFLICT,
                "not_approved",
                "This device isn't approved under the current history key",
            ),
            KeyDirectoryError::RecipientNotApproved => ApiError::new(
                StatusCode::CONFLICT,
                "not_approved",
                "The device isn't approved under the current history key",
            ),
            KeyDirectoryError::NotTheApprover => ApiError::new(
                StatusCode::CONFLICT,
                "not_the_approver",
                "Only a device that approved this one shares the history key with it",
            ),
            KeyDirectoryError::ShareUnsigned => {
                ApiError::bad_request("signature does not verify over the share")
            }
            KeyDirectoryError::NoKeyShare => ApiError::not_found("No key share for this device"),
            KeyDirectoryError::Request(refusal) => request_refused(refusal),
            KeyDirectoryError::StartOver(refusal) => start_over_refused(refusal),
            KeyDirectoryError::ApprovalRequired(_) => approval_required(),
            KeyDirectoryError::DeviceRequired(_) => device_required(),
            KeyDirectoryError::StaleHistoryKey(_) => stale_history_key(),
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
