//! Avatar upload and deletion handlers.

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::Serialize;

use idp_db::repos::users;

use crate::federation::auth::require_auth;
use crate::{AppState, OidcError};

const MAX_AVATAR_SIZE: usize = 2 * 1024 * 1024; // 2 MiB

#[derive(Debug, Serialize)]
pub struct AvatarResponse {
    pub avatar_url: String,
}

/// PUT /api/avatar
///
/// Upload or replace the authenticated user's avatar.
/// Body: raw image bytes. Content-Type header must be image/jpeg, image/png, image/webp, or image/gif.
#[tracing::instrument(skip_all)]
pub async fn put_avatar(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<AvatarResponse>), OidcError> {
    let user_id = require_auth(&state, &headers).await?;

    let storage = state
        .storage
        .as_ref()
        .ok_or_else(|| OidcError::server_error("Object storage not configured"))?;

    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| OidcError::invalid_request("Content-Type header is required"))?;

    if !["image/jpeg", "image/png", "image/webp", "image/gif"].contains(&content_type) {
        return Err(OidcError::invalid_request(
            "Content-Type must be image/jpeg, image/png, image/webp, or image/gif",
        ));
    }

    if body.is_empty() {
        return Err(OidcError::invalid_request("Body cannot be empty"));
    }
    if body.len() > MAX_AVATAR_SIZE {
        return Err(OidcError::invalid_request("Avatar must be under 2 MiB"));
    }

    // Delete any previous avatar (may have a different extension)
    storage
        .delete_avatar(user_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    // Upload new avatar
    let avatar_url = storage
        .upload_avatar(user_id, body.to_vec(), content_type)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    // Persist URL in database
    users::update_avatar_url(&state.pool, user_id, &avatar_url)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    tracing::info!(user_id = %user_id, "avatar updated");

    Ok((StatusCode::OK, Json(AvatarResponse { avatar_url })))
}

/// DELETE /api/avatar
///
/// Remove the authenticated user's avatar.
#[tracing::instrument(skip_all)]
pub async fn delete_avatar(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<StatusCode, OidcError> {
    let user_id = require_auth(&state, &headers).await?;

    let storage = state
        .storage
        .as_ref()
        .ok_or_else(|| OidcError::server_error("Object storage not configured"))?;

    storage
        .delete_avatar(user_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    users::clear_avatar_url(&state.pool, user_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    tracing::info!(user_id = %user_id, "avatar deleted");

    Ok(StatusCode::NO_CONTENT)
}
