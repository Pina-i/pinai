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

use crate::ApiError;
use crate::auth::{RecentlySignedIn, SignedIn};

#[derive(Deserialize)]
pub struct DeviceBody {
    device_id: Uuid,
}

/// `PUT /api/sessions/current/device`
pub async fn link_device(
    State(link): State<Arc<LinkDevice>>,
    SignedIn(bearer): SignedIn,
    Json(body): Json<DeviceBody>,
) -> Result<StatusCode, ApiError> {
    link.execute(bearer, body.device_id.into(), OffsetDateTime::now_utc())
        .await
        .map_err(|e| match e {
            AuthError::DeviceRefused => ApiError::new(
                StatusCode::FORBIDDEN,
                "access_denied",
                "Not one of your devices, or revoked",
            ),
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
        .map_err(|e| ApiError::internal(anyhow::Error::from(e)))?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests;
