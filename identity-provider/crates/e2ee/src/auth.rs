//! Auth helpers for the key-directory endpoints.
//!
//! Some endpoints accept either Bearer (the local user) or HTTP-Signature
//! (a peer IdP federating). `Requester::User` and `Requester::Peer` both
//! carry enough identity to be used as a rate-limit key.

use axum::http::HeaderMap;
use uuid::Uuid;

use idp_federation::auth::require_auth;
use idp_federation::http_signature::verify_http_signature;
use idp_state::{AppState, OidcError};

/// Authenticated identity of an incoming request.
#[derive(Debug, Clone)]
pub enum Requester {
    User(Uuid),
    Peer(String),
}

impl Requester {
    /// Stable string used to bucket rate-limit attempts. `user:<uuid>` for
    /// local users; `peer:<keyId>` for peer IdPs.
    pub fn rate_limit_key(&self) -> String {
        match self {
            Self::User(id) => format!("user:{id}"),
            Self::Peer(key_id) => format!("peer:{key_id}"),
        }
    }
}

/// Accept either Bearer (local user) or HTTP-Sig (peer IdP). Bearer wins on
/// presence — peers MUST NOT also send a Bearer token, so trying Bearer
/// first is safe.
pub async fn require_user_or_peer(
    state: &AppState,
    headers: &HeaderMap,
    method: &str,
    path: &str,
) -> Result<Requester, OidcError> {
    if headers.get("Authorization").is_some() {
        return require_auth(state, headers).await.map(Requester::User);
    }
    Ok(Requester::Peer(
        verify_http_signature(headers, method, path).await?,
    ))
}
