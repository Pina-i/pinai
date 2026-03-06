use axum::{extract::State, http::HeaderMap, Json};
use serde::Serialize;
use uuid::Uuid;

use idp_db::repos::users;
use jwt_utils::validate_access_token;

use crate::{AppState, OidcError};

#[derive(Debug, Serialize)]
pub struct UserinfoResponse {
    pub sub: String,
    pub email: String,
    pub preferred_username: String,
    pub address: String,
    pub avatar_url: Option<String>,
}

/// GET /userinfo
///
/// Validates the Bearer access token and returns the user's claims.
#[tracing::instrument(skip_all)]
pub async fn get_userinfo(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<UserinfoResponse>, OidcError> {
    // 1. Extract Bearer token from Authorization header
    let token = extract_bearer_token(&headers)
        .ok_or_else(|| OidcError::invalid_client("Missing or invalid Authorization header"))?;

    // 2. Validate the access token
    let issuer = state.config.issuer();
    let claims = validate_access_token(token, &state.keypair, &issuer, "web-client")
        .map_err(|_| OidcError::invalid_client("Invalid or expired access token"))?;

    tracing::debug!(sub = %claims.sub, "access token validated");

    // 3. Look up the user (sub is the UUID string)
    let user_id: Uuid = claims
        .sub
        .parse()
        .map_err(|_| OidcError::invalid_client("Invalid subject claim"))?;

    let user = users::find_by_id(&state.pool, user_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::invalid_client("User not found"))?;

    tracing::debug!(user_id = %user_id, username = %user.username, "userinfo returned");

    let address = user.address(&state.config.domain);
    Ok(Json(UserinfoResponse {
        sub: user.id.to_string(),
        email: user.email,
        preferred_username: user.username,
        address,
        avatar_url: user.avatar_url,
    }))
}

fn extract_bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
}
