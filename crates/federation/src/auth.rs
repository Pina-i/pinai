//! Bearer-token authentication helper shared by all federation REST handlers.

use axum::http::HeaderMap;
use uuid::Uuid;

use jwt_utils::validate_access_token;

use idp_state::{AppState, OidcError};

/// Extract and validate the Bearer access token from the `Authorization` header.
/// Returns the authenticated user's UUID.
pub async fn require_auth(state: &AppState, headers: &HeaderMap) -> Result<Uuid, OidcError> {
    let token = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| OidcError::invalid_client("Missing or invalid Authorization header"))?;

    let issuer = state.config.issuer();
    // audience is not strictly enforced for the social-graph API (any valid token works)
    let claims = validate_access_token(token, &state.keypair, &issuer, "web-client")
        .map_err(|_| OidcError::invalid_client("Invalid or expired access token"))?;

    claims
        .sub
        .parse::<Uuid>()
        .map_err(|_| OidcError::invalid_client("Invalid subject claim"))
}
