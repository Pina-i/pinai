//! User search. Bearer-auth.

use axum::{
    extract::{Query, State},
    http::HeaderMap,
    Json,
};
use serde::{Deserialize, Serialize};

use idp_db::repos::users;
use idp_federation::auth::require_auth;
use idp_state::{AppState, OidcError};

// ─── Search users ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct SearchQuery {
    pub q: String,
    #[serde(default = "default_limit")]
    pub limit: i64,
}
fn default_limit() -> i64 {
    20
}

#[derive(Debug, Serialize)]
pub struct UserSummary {
    pub actor_uri: String,
    pub username: String,
    pub display_name: Option<String>,
}

/// GET /api/users/search?q={query}
#[tracing::instrument(skip_all)]
pub async fn search_users(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<SearchQuery>,
) -> Result<Json<Vec<UserSummary>>, OidcError> {
    require_auth(&state, &headers).await?;

    let limit = params.limit.clamp(1, 50);
    let results = users::search_by_username(&state.pool, &params.q, limit)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    Ok(Json(
        results
            .into_iter()
            .map(|u| UserSummary {
                actor_uri: u.actor_uri.unwrap_or_default(),
                username: u.username,
                display_name: u.display_name,
            })
            .collect(),
    ))
}
