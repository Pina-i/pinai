//! `POST /api/keys/identity` (Bearer) and
//! `GET  /api/keys/identity/:actor_uri` (Bearer or HTTP-Sig).
//!
//! Publishes / serves the user-controlled MSK / SSK / USK public-key triple
//! plus the SSK-and-USK self-signatures. All bytes are wire-encoded as
//! base64 strings on the JSON envelope; the database holds raw `BYTEA`.

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tracing::instrument;

use idp_db::repos::{user_identity_keys, users};
use idp_federation::auth::require_auth;
use idp_state::{AppState, OidcError};

use crate::auth::require_user_or_peer;

#[derive(Debug, Deserialize)]
pub struct PublishIdentityRequest {
    pub msk_public: String,
    pub ssk_public: String,
    pub ssk_signature: String,
    pub usk_public: String,
    pub usk_signature: String,
}

#[derive(Debug, Serialize)]
pub struct IdentityKeysResponse {
    pub actor_uri: String,
    pub msk_public: String,
    pub ssk_public: String,
    pub ssk_signature: String,
    pub usk_public: String,
    pub usk_signature: String,
    #[serde(with = "time::serde::rfc3339")]
    pub published_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub rotated_at: OffsetDateTime,
}

#[instrument(skip_all)]
pub async fn post_identity(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<PublishIdentityRequest>,
) -> Result<StatusCode, OidcError> {
    let user_id = require_auth(&state, &headers).await?;

    let msk = decode("msk_public", &body.msk_public)?;
    let ssk = decode("ssk_public", &body.ssk_public)?;
    let ssk_sig = decode("ssk_signature", &body.ssk_signature)?;
    let usk = decode("usk_public", &body.usk_public)?;
    let usk_sig = decode("usk_signature", &body.usk_signature)?;

    user_identity_keys::upsert(&state.pool, user_id, &msk, &ssk, &ssk_sig, &usk, &usk_sig)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    tracing::info!(user_id = %user_id, "identity keys published / rotated");
    Ok(StatusCode::NO_CONTENT)
}

#[instrument(skip_all, fields(actor_uri = %actor_uri))]
pub async fn get_identity(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(actor_uri): Path<String>,
) -> Result<Json<IdentityKeysResponse>, OidcError> {
    // Either Bearer (local user fetching for first-contact pin) or HTTP-Sig
    // (peer IdP fetching to add this user to a group on the other side).
    let path = format!("/api/keys/identity/{actor_uri}");
    let _ = require_user_or_peer(&state, &headers, "get", &path).await?;

    let user = users::find_by_actor_uri(&state.pool, &actor_uri)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::not_found("User not found"))?;

    let row = user_identity_keys::find_by_user_id(&state.pool, user.id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::not_found("Identity keys not published"))?;

    Ok(Json(IdentityKeysResponse {
        actor_uri,
        msk_public: B64.encode(&row.msk_public),
        ssk_public: B64.encode(&row.ssk_public),
        ssk_signature: B64.encode(&row.ssk_signature),
        usk_public: B64.encode(&row.usk_public),
        usk_signature: B64.encode(&row.usk_signature),
        published_at: row.published_at,
        rotated_at: row.rotated_at,
    }))
}

/// Decode a base64 field, mapping decode errors to `400 invalid_request`.
fn decode(field: &str, value: &str) -> Result<Vec<u8>, OidcError> {
    B64.decode(value)
        .map_err(|_| OidcError::invalid_request(format!("`{field}` is not valid base64")))
}
