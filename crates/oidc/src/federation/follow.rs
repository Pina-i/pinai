//! REST API handlers for the social graph (follow / unfollow / accept / reject).
//!
//! All endpoints require a valid Bearer access token.

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use idp_db::repos::{follows, users};

use crate::ws::events::{FollowPayload, WsEvent};
use crate::{AppState, OidcError};

use super::auth::require_auth;

// ─── Search users ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct SearchQuery {
    pub q: String,
    #[serde(default = "default_limit")]
    pub limit: i64,
}
fn default_limit() -> i64 { 20 }

#[derive(Debug, Serialize)]
pub struct UserSummary {
    pub handle: String,
    pub username: String,
}

/// GET /api/users/search?q={query}
#[tracing::instrument(skip_all)]
pub async fn search_users(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<SearchQuery>,
) -> Result<Json<Vec<UserSummary>>, OidcError> {
    require_auth(&state, &headers).await?;

    let limit = params.limit.min(50).max(1);
    let results = users::search_by_username(&state.pool, &params.q, limit)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    Ok(Json(results.into_iter().map(|u| UserSummary {
        handle: u.handle(),
        username: u.username,
    }).collect()))
}

// ─── Send follow request ──────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct FollowRequest {
    /// Handle of the user to follow, e.g. "alice-A1B2".
    pub handle: String,
}

#[derive(Debug, Serialize)]
pub struct FollowResponse {
    pub follow_id: Uuid,
    pub state: String,
}

/// POST /api/follow
/// Body: `{ "handle": "alice-A1B2" }`
#[tracing::instrument(skip_all)]
pub async fn post_follow(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<FollowRequest>,
) -> Result<(StatusCode, Json<FollowResponse>), OidcError> {
    let caller_id = require_auth(&state, &headers).await?;

    let target = users::find_by_handle(&state.pool, &body.handle)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::not_found("User not found"))?;

    if target.id == caller_id {
        return Err(OidcError::invalid_request("Cannot follow yourself"));
    }

    // Build an AP activity ID for the follow (for federation traceability).
    let activity_id = format!(
        "{}/users/{}/follows/{}",
        state.config.issuer(),
        caller_id,
        target.id,
    );

    let follow = follows::send_follow_request(
        &state.pool,
        caller_id,
        target.id,
        Some(&activity_id),
    )
    .await
    .map_err(|e| OidcError::server_error(e.to_string()))?;

    // For local users, auto-accept the follow.
    let follow = follows::set_follow_state(&state.pool, follow.id, "accepted")
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::server_error("Follow not found after insert"))?;

    // Notify target via WebSocket (follow request + auto-accepted).
    let caller = users::find_by_id(&state.pool, caller_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::server_error("Caller not found"))?;

    let payload = FollowPayload {
        follow_id: follow.id,
        handle: caller.handle(),
        username: caller.username,
    };
    state.hub.send_to_user(&target.id, WsEvent::FollowRequest(payload.clone()));
    state.hub.send_to_user(&target.id, WsEvent::FollowAccepted(payload));

    tracing::info!(caller = %caller_id, target = %target.id, "follow request sent + accepted (local)");

    Ok((StatusCode::CREATED, Json(FollowResponse {
        follow_id: follow.id,
        state: follow.state,
    })))
}

// ─── Unfollow ─────────────────────────────────────────────────────────────────

/// DELETE /api/follow/:handle
#[tracing::instrument(skip_all, fields(handle = %handle))]
pub async fn delete_follow(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(handle): Path<String>,
) -> Result<StatusCode, OidcError> {
    let caller_id = require_auth(&state, &headers).await?;

    let target = users::find_by_handle(&state.pool, &handle)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::not_found("User not found"))?;

    follows::delete_follow(&state.pool, caller_id, target.id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    // Notify target that they lost a follower.
    let caller = users::find_by_id(&state.pool, caller_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;
    if let Some(caller) = caller {
        state.hub.send_to_user(&target.id, WsEvent::FollowRemoved(FollowPayload {
            follow_id: Uuid::nil(),
            handle: caller.handle(),
            username: caller.username,
        }));
    }

    tracing::info!(caller = %caller_id, target = %target.id, "unfollowed");
    Ok(StatusCode::NO_CONTENT)
}

// ─── Incoming follow requests ─────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct FollowRequestSummary {
    pub follow_id: Uuid,
    pub follower_handle: String,
    pub follower_username: String,
    pub state: String,
}

/// GET /api/follow/incoming — pending follow requests aimed at me
#[tracing::instrument(skip_all)]
pub async fn get_incoming_requests(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<FollowRequestSummary>>, OidcError> {
    let caller_id = require_auth(&state, &headers).await?;

    let rows = follows::get_incoming_requests(&state.pool, caller_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    let mut summaries = Vec::with_capacity(rows.len());
    for row in rows {
        if let Some(follower) = users::find_by_id(&state.pool, row.follower_id)
            .await
            .map_err(|e| OidcError::server_error(e.to_string()))?
        {
            summaries.push(FollowRequestSummary {
                follow_id: row.id,
                follower_handle: follower.handle(),
                follower_username: follower.username,
                state: row.state,
            });
        }
    }

    Ok(Json(summaries))
}

// ─── Accept / Reject ──────────────────────────────────────────────────────────

/// POST /api/follow/:follow_id/accept
#[tracing::instrument(skip_all, fields(follow_id = %follow_id))]
pub async fn accept_follow(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(follow_id): Path<Uuid>,
) -> Result<StatusCode, OidcError> {
    let caller_id = require_auth(&state, &headers).await?;

    let follow = follows::find_by_id(&state.pool, follow_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::not_found("Follow request not found"))?;

    // Caller must be the follow target.
    if follow.following_id != caller_id {
        return Err(OidcError::invalid_request("Not authorised to accept this follow"));
    }

    follows::set_follow_state(&state.pool, follow.id, "accepted")
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    // Notify the follower their request was accepted.
    let caller = users::find_by_id(&state.pool, caller_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;
    if let Some(caller) = caller {
        state.hub.send_to_user(&follow.follower_id, WsEvent::FollowAccepted(FollowPayload {
            follow_id: follow.id,
            handle: caller.handle(),
            username: caller.username,
        }));
    }

    tracing::info!(follow_id = %follow_id, "follow accepted");
    Ok(StatusCode::NO_CONTENT)
}

/// POST /api/follow/:follow_id/reject
#[tracing::instrument(skip_all, fields(follow_id = %follow_id))]
pub async fn reject_follow(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(follow_id): Path<Uuid>,
) -> Result<StatusCode, OidcError> {
    let caller_id = require_auth(&state, &headers).await?;

    let follow = follows::find_by_id(&state.pool, follow_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::not_found("Follow request not found"))?;

    if follow.following_id != caller_id {
        return Err(OidcError::invalid_request("Not authorised to reject this follow"));
    }

    follows::set_follow_state(&state.pool, follow.id, "rejected")
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    // Notify the follower their request was rejected.
    let caller = users::find_by_id(&state.pool, caller_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;
    if let Some(caller) = caller {
        state.hub.send_to_user(&follow.follower_id, WsEvent::FollowRejected(FollowPayload {
            follow_id: follow.id,
            handle: caller.handle(),
            username: caller.username,
        }));
    }

    tracing::info!(follow_id = %follow_id, "follow rejected");
    Ok(StatusCode::NO_CONTENT)
}

// ─── Following / Followers lists ──────────────────────────────────────────────

/// GET /api/following — accounts I follow (accepted)
#[tracing::instrument(skip_all)]
pub async fn get_following(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<UserSummary>>, OidcError> {
    let caller_id = require_auth(&state, &headers).await?;

    let rows = follows::get_following(&state.pool, caller_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    load_user_summaries(&state, rows.iter().map(|r| r.following_id)).await
}

/// GET /api/followers — my accepted followers
#[tracing::instrument(skip_all)]
pub async fn get_followers(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<UserSummary>>, OidcError> {
    let caller_id = require_auth(&state, &headers).await?;

    let rows = follows::get_followers(&state.pool, caller_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    load_user_summaries(&state, rows.iter().map(|r| r.follower_id)).await
}

async fn load_user_summaries(
    state: &AppState,
    ids: impl Iterator<Item = Uuid>,
) -> Result<Json<Vec<UserSummary>>, OidcError> {
    let mut summaries = Vec::new();
    for id in ids {
        if let Some(u) = users::find_by_id(&state.pool, id)
            .await
            .map_err(|e| OidcError::server_error(e.to_string()))?
        {
            summaries.push(UserSummary { handle: u.handle(), username: u.username });
        }
    }
    Ok(Json(summaries))
}
