//! HTTP handlers for presence endpoints.
//!
//! - `GET /api/presence?actors[]=...` — Bearer-auth, returns current presence for requested actors.
//! - `POST /api/presence/batch` — HTTP Signature auth (server-to-server), returns presence snapshot.

use axum::{
    extract::{Query, State},
    http::HeaderMap,
    Json,
};

use crate::error::OidcError;
use crate::federation::auth::require_auth;
use crate::AppState;

use super::types::{ActorPresence, PresenceBatchRequest, PresenceQuery, PresenceResponse};

/// `GET /api/presence?actors[]=...`
///
/// Bearer-auth. Returns the current presence state for the requested actors.
/// Used by clients on page load to populate the friends list before WS events arrive.
#[tracing::instrument(skip_all, fields(actor_count))]
pub async fn get_presence(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<PresenceQuery>,
) -> Result<Json<PresenceResponse>, OidcError> {
    // Require authenticated user
    let _user_id = require_auth(&state, &headers).await?;

    let store = state
        .presence_store
        .as_ref()
        .ok_or_else(|| OidcError::server_error("presence not available"))?;

    tracing::Span::current().record("actor_count", query.actors.len());

    let presence: Vec<ActorPresence> = query
        .actors
        .iter()
        .map(|uri| ActorPresence {
            actor_uri: uri.clone(),
            state: store.get(uri),
        })
        .collect();

    Ok(Json(PresenceResponse { presence }))
}

/// `POST /api/presence/batch`
///
/// HTTP Signature auth (server-to-server). Returns a presence snapshot for the requested actors.
/// Used by remote IdPs for periodic batch polling (tiered hybrid scaling strategy).
#[tracing::instrument(skip_all, fields(actor_count))]
pub async fn post_presence_batch(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<PresenceBatchRequest>,
) -> Result<Json<PresenceResponse>, OidcError> {
    // Verify HTTP Signature
    verify_http_signature(&state, &headers, "post", "/api/presence/batch").await?;

    let store = state
        .presence_store
        .as_ref()
        .ok_or_else(|| OidcError::server_error("presence not available"))?;

    tracing::Span::current().record("actor_count", body.actors.len());

    let presence: Vec<ActorPresence> = body
        .actors
        .iter()
        .map(|uri| ActorPresence {
            actor_uri: uri.clone(),
            state: store.get(uri),
        })
        .collect();

    Ok(Json(PresenceResponse { presence }))
}

/// Verify an incoming HTTP Signature by fetching the signer's public key from their actor document.
pub async fn verify_http_signature(
    _state: &AppState,
    headers: &HeaderMap,
    method: &str,
    path: &str,
) -> Result<String, OidcError> {
    let sig_header = headers
        .get("signature")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| OidcError::invalid_request("missing Signature header"))?;

    let parsed = http_signatures::parse_signature_header(sig_header)
        .map_err(|e| OidcError::invalid_request(format!("invalid Signature header: {e}")))?;

    // Fetch the actor document to get the public key
    let key_id = &parsed.key_id;
    let actor_url = key_id
        .split('#')
        .next()
        .ok_or_else(|| OidcError::invalid_request("invalid keyId format"))?;

    let client = reqwest::Client::new();
    let actor_doc: serde_json::Value = client
        .get(actor_url)
        .header("Accept", "application/activity+json")
        .send()
        .await
        .map_err(|e| OidcError::server_error(format!("failed to fetch actor: {e}")))?
        .json()
        .await
        .map_err(|e| OidcError::server_error(format!("failed to parse actor: {e}")))?;

    let public_key_pem = actor_doc
        .get("publicKey")
        .and_then(|pk| pk.get("publicKeyPem"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| OidcError::invalid_request("actor has no publicKeyPem"))?;

    // Verify the signature
    let get_header = |name: &str| -> Option<String> {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    };

    http_signatures::verify_request(method, path, sig_header, get_header, public_key_pem)
        .map_err(|e| OidcError::access_denied(format!("signature verification failed: {e}")))?;

    Ok(key_id.to_string())
}
