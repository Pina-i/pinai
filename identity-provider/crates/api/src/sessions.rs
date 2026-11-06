//! The caller's sessions: which device each signed in, and signing out of the others — see
//! identity-provider/specs/auth.md § 1 "Sessions and devices".

use std::sync::Arc;

use application::auth::{LinkDevice, SignOutOthers};
use axum::Json;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use domain::auth::AuthError;
use serde::Deserialize;
use time::OffsetDateTime;
use uuid::Uuid;

use domain::e2ee::Ed25519Signature;

use crate::ApiError;
use crate::auth::{RecentlySignedIn, SignedIn};
use crate::e2ee::{approval_required, base64_field};

#[derive(Deserialize)]
pub struct DeviceBody {
    device_id: Uuid,
    /// Standard base64 of the device's root key's signature over the session's naming bytes.
    signature: Option<String>,
}

/// `PUT /api/sessions/current/device`
pub async fn link_device(
    State(link): State<Arc<LinkDevice>>,
    SignedIn(bearer): SignedIn,
    Json(body): Json<DeviceBody>,
) -> Result<StatusCode, ApiError> {
    // A signature that isn't one proves nothing, as a wrong one doesn't.
    let proof = body.signature.as_deref().and_then(|raw| {
        base64_field("signature", raw, |bytes| {
            Ed25519Signature::parse("signature", bytes)
        })
        .ok()
    });
    link.execute(
        bearer,
        body.device_id.into(),
        proof,
        OffsetDateTime::now_utc(),
    )
    .await
    .map_err(|e| match e {
        AuthError::DeviceRefused => ApiError::new(
            StatusCode::FORBIDDEN,
            "access_denied",
            "Not one of your devices, or revoked",
        ),
        AuthError::DeviceMismatch => ApiError::new(
            StatusCode::FORBIDDEN,
            "device_mismatch",
            "This session signed in another device",
        ),
        AuthError::DeviceProofInvalid => ApiError::new(
            StatusCode::FORBIDDEN,
            "device_proof_invalid",
            "The signature does not prove this device's root key",
        ),
        AuthError::SessionEnded => ApiError::invalid_token("The session has ended", true),
        other => ApiError::internal(anyhow::Error::from(other)),
    })?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct SignOutParams {
    keep: Option<String>,
}

/// `DELETE /api/sessions?keep=current` — every session but the caller's.
pub async fn sign_out_others(
    State(sign_out): State<Arc<SignOutOthers>>,
    RecentlySignedIn(bearer): RecentlySignedIn,
    Query(params): Query<SignOutParams>,
) -> Result<StatusCode, ApiError> {
    if params.keep.as_deref() != Some("current") {
        return Err(ApiError::bad_request("keep=current is required"));
    }
    sign_out
        .execute(bearer, OffsetDateTime::now_utc())
        .await
        .map_err(|e| match e {
            AuthError::ApprovalRequired(_) => approval_required(),
            other => ApiError::internal(anyhow::Error::from(other)),
        })?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests;
