use axum::{extract::State, Json};
use serde::Serialize;

use crate::{AppState, OidcError};
use jwt_utils::JwkSet;

/// OIDC Discovery document per OpenID Connect Discovery 1.0 §4.
#[derive(Debug, Serialize)]
pub struct OidcConfiguration {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub jwks_uri: String,
    pub registration_endpoint: String,
    pub scopes_supported: Vec<&'static str>,
    pub response_types_supported: Vec<&'static str>,
    pub grant_types_supported: Vec<&'static str>,
    pub subject_types_supported: Vec<&'static str>,
    pub id_token_signing_alg_values_supported: Vec<&'static str>,
    pub claims_supported: Vec<&'static str>,
    pub code_challenge_methods_supported: Vec<&'static str>,
    pub token_endpoint_auth_methods_supported: Vec<&'static str>,
}

/// GET /.well-known/openid-configuration
#[tracing::instrument(skip_all)]
pub async fn openid_configuration(
    State(state): State<AppState>,
) -> Result<Json<OidcConfiguration>, OidcError> {
    let base = state.config.issuer();
    tracing::debug!(issuer = %base, "serving OIDC discovery document");
    Ok(Json(OidcConfiguration {
        issuer: base.clone(),
        authorization_endpoint: format!("{base}/authorize"),
        token_endpoint: format!("{base}/token"),
        userinfo_endpoint: format!("{base}/userinfo"),
        jwks_uri: format!("{base}/.well-known/jwks.json"),
        registration_endpoint: format!("{base}/register"),
        scopes_supported: vec!["openid", "profile", "email"],
        response_types_supported: vec!["code"],
        grant_types_supported: vec!["authorization_code"],
        subject_types_supported: vec!["public"],
        id_token_signing_alg_values_supported: vec!["EdDSA"],
        claims_supported: vec!["sub", "iss", "aud", "exp", "iat", "email", "preferred_username", "nonce"],
        code_challenge_methods_supported: vec!["S256"],
        token_endpoint_auth_methods_supported: vec!["none"],
    }))
}

/// GET /.well-known/jwks.json
#[tracing::instrument(skip_all)]
pub async fn jwks(State(state): State<AppState>) -> Json<JwkSet> {
    tracing::debug!(kid = %state.keypair.kid, "serving JWKS");
    Json(JwkSet::from_keypairs(&[&state.keypair]))
}
