//! Recovery Key endpoints — opt-in passphrase-wrapped MSK backup.
//!
//! - `PUT    /api/keys/recovery` (Bearer) — set or replace the wrapped blob.
//! - `GET    /api/keys/recovery` (Bearer) — fetch it for offline decryption.
//! - `DELETE /api/keys/recovery` (Bearer) — opt out / clear.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::json;
use time::OffsetDateTime;
use tracing::instrument;

use idp_db::repos::recovery_blobs;
use idp_federation::auth::require_auth;
use idp_state::{AppState, OidcError};

#[derive(Debug, Deserialize, Serialize)]
pub struct Argon2Params {
    /// Memory cost in KiB.
    pub m_kib: u32,
    /// Time cost (iterations).
    pub t: u32,
    /// Parallelism.
    pub p: u32,
}

#[derive(Debug, Deserialize)]
pub struct PutRecoveryRequest {
    pub wrapped_msk: String,
    pub salt: String,
    pub argon2_params: Argon2Params,
}

#[derive(Debug, Serialize)]
pub struct GetRecoveryResponse {
    pub wrapped_msk: String,
    pub salt: String,
    pub argon2_params: Argon2Params,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

#[instrument(skip_all)]
pub async fn put_recovery(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<PutRecoveryRequest>,
) -> Result<StatusCode, OidcError> {
    let user_id = require_auth(&state, &headers).await?;

    let wrapped = B64
        .decode(&body.wrapped_msk)
        .map_err(|_| OidcError::invalid_request("`wrapped_msk` is not valid base64"))?;
    if wrapped.is_empty() {
        return Err(OidcError::invalid_request("`wrapped_msk` is empty"));
    }
    let salt = B64
        .decode(&body.salt)
        .map_err(|_| OidcError::invalid_request("`salt` is not valid base64"))?;
    if salt.len() < 16 {
        return Err(OidcError::invalid_request("`salt` must be at least 16 bytes"));
    }
    if body.argon2_params.t == 0 || body.argon2_params.p == 0 || body.argon2_params.m_kib == 0 {
        return Err(OidcError::invalid_request("argon2 params must all be non-zero"));
    }

    let params_json = json!({
        "m_kib": body.argon2_params.m_kib,
        "t":     body.argon2_params.t,
        "p":     body.argon2_params.p,
    });

    recovery_blobs::upsert(&state.pool, user_id, &wrapped, &salt, &params_json)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    tracing::info!(user_id = %user_id, "recovery key set / rotated");
    Ok(StatusCode::NO_CONTENT)
}

#[instrument(skip_all)]
pub async fn get_recovery(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<GetRecoveryResponse>, OidcError> {
    let user_id = require_auth(&state, &headers).await?;

    let blob = recovery_blobs::find_by_user_id(&state.pool, user_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::not_found("Recovery Key not configured"))?;

    let argon2_params: Argon2Params = serde_json::from_value(blob.argon2_params)
        .map_err(|e| OidcError::server_error(format!("malformed argon2_params row: {e}")))?;

    Ok(Json(GetRecoveryResponse {
        wrapped_msk: B64.encode(&blob.wrapped_msk),
        salt: B64.encode(&blob.salt),
        argon2_params,
        created_at: blob.created_at,
        updated_at: blob.updated_at,
    }))
}

#[instrument(skip_all)]
pub async fn delete_recovery(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<StatusCode, OidcError> {
    let user_id = require_auth(&state, &headers).await?;

    let removed = recovery_blobs::delete(&state.pool, user_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    if removed {
        tracing::info!(user_id = %user_id, "recovery key cleared");
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(OidcError::not_found("Recovery Key not configured"))
    }
}
