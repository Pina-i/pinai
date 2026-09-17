use axum::{extract::State, Form, Json};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use idp_db::repos::{auth_codes, clients, users};
use jwt_utils::{issue_access_token, issue_id_token, verify_pkce};

use crate::{AppState, OidcError};

/// Token request form body (application/x-www-form-urlencoded).
#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    pub code: String,
    pub redirect_uri: String,
    pub client_id: String,
    pub code_verifier: String,
}

/// Successful token response.
#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: i64,
    pub id_token: String,
}

/// POST /token
#[tracing::instrument(skip_all, fields(client_id = %form.client_id, grant_type = %form.grant_type))]
pub async fn post_token(
    State(state): State<AppState>,
    Form(form): Form<TokenRequest>,
) -> Result<Json<TokenResponse>, OidcError> {
    // 1. Validate grant_type
    if form.grant_type != "authorization_code" {
        return Err(OidcError::invalid_request(
            "grant_type must be 'authorization_code'",
        ));
    }

    // 2. Validate client exists
    clients::find_client_by_id(&state.pool, &form.client_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::invalid_client("Unknown client_id"))?;

    tracing::debug!("client validated");

    // 3. Validate redirect_uri against client's registered URIs
    let uri_valid =
        clients::validate_redirect_uri(&state.pool, &form.client_id, &form.redirect_uri)
            .await
            .map_err(|e| OidcError::server_error(e.to_string()))?;
    if !uri_valid {
        return Err(OidcError::invalid_grant("redirect_uri mismatch"));
    }

    // 4. Consume the authorization code atomically (prevents replay)
    let auth_code = auth_codes::consume_code(&state.pool, &form.code)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| {
            OidcError::invalid_grant("Authorization code is invalid, expired, or already used")
        })?;

    tracing::debug!(user_id = %auth_code.user_id, "auth code consumed");

    // 5. Verify client_id and redirect_uri match what was in the auth code
    if auth_code.client_id != form.client_id {
        return Err(OidcError::invalid_grant("client_id mismatch"));
    }
    if auth_code.redirect_uri != form.redirect_uri {
        return Err(OidcError::invalid_grant("redirect_uri mismatch"));
    }

    // 6. Verify PKCE — constant-time comparison
    verify_pkce(&form.code_verifier, &auth_code.code_challenge)
        .map_err(|_| OidcError::invalid_grant("code_verifier does not match code_challenge"))?;

    tracing::debug!("PKCE verified");

    // 7. Load the user
    let user_id: Uuid = auth_code.user_id;
    let user = users::find_by_id(&state.pool, user_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::server_error("User not found"))?;

    let issuer = state.config.issuer();
    let sub = user.id.to_string();
    const TTL: i64 = 3600;

    // 8. Issue access token
    let access_token = issue_access_token(
        &state.keypair,
        &issuer,
        &sub,
        &form.client_id,
        &user.email,
        &user.username,
        TTL,
    )
    .map_err(|e| OidcError::server_error(e.to_string()))?;

    // 9. Issue ID token (includes nonce if present)
    let id_token = issue_id_token(
        &state.keypair,
        &issuer,
        &sub,
        &form.client_id,
        &user.email,
        &user.username,
        auth_code.nonce.clone(),
        TTL,
    )
    .map_err(|e| OidcError::server_error(e.to_string()))?;

    tracing::info!(user_id = %user_id, ttl = TTL, "access token and ID token issued");

    Ok(Json(TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: TTL,
        id_token,
    }))
}
