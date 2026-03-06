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

use activitypub::Activity;
use idp_db::models::handle_from_address;
use idp_db::repos::{follows, users};

use crate::ws::events::{FollowPayload, WsEvent};
use crate::{AppState, OidcError};

use super::auth::require_auth;
use super::delivery;

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
    pub address: String,
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

    let domain = &state.config.domain;
    Ok(Json(results.into_iter().map(|u| UserSummary {
        address: u.address(domain),
        username: u.username,
    }).collect()))
}

// ─── Send follow request ──────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct FollowRequest {
    /// Full address of the user to follow, e.g. `"alice-A1B2@idp.example.com"`.
    pub address: String,
}

#[derive(Debug, Serialize)]
pub struct FollowResponse {
    pub follow_id: Uuid,
    pub state: String,
}

/// POST /api/follow
/// Body: `{ "address": "alice-A1B2@localhost:8080" }` (local) or `{ "address": "bob-X1Y2@remote:8081" }` (remote)
#[tracing::instrument(skip_all)]
pub async fn post_follow(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<FollowRequest>,
) -> Result<(StatusCode, Json<FollowResponse>), OidcError> {
    let caller_id = require_auth(&state, &headers).await?;

    // Parse address into handle + domain.
    if let Some((handle, domain)) = body.address.split_once('@') {
        // Check if the domain is our own — if so, treat as local.
        if domain == state.config.domain {
            return follow_local(&state, caller_id, handle).await;
        }
        return follow_remote(&state, caller_id, handle, domain).await;
    }

    // Fallback: bare handle (legacy / same-IdP shorthand).
    follow_local(&state, caller_id, &body.address).await
}

/// Follow a user on the same IdP (auto-accept).
async fn follow_local(
    state: &AppState,
    caller_id: Uuid,
    handle: &str,
) -> Result<(StatusCode, Json<FollowResponse>), OidcError> {
    let target = users::find_by_handle(&state.pool, handle)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::not_found("User not found"))?;

    if target.id == caller_id {
        return Err(OidcError::invalid_request("Cannot follow yourself"));
    }

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

    // Local users: auto-accept.
    let follow = follows::set_follow_state(&state.pool, follow.id, "accepted")
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::server_error("Follow not found after insert"))?;

    // Notify target via WebSocket.
    let caller = users::find_by_id(&state.pool, caller_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::server_error("Caller not found"))?;

    let domain = &state.config.domain;
    let payload = FollowPayload {
        follow_id: follow.id,
        address: caller.address(domain),
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

/// Follow a user on a remote IdP via ActivityPub federation.
async fn follow_remote(
    state: &AppState,
    caller_id: Uuid,
    handle: &str,
    domain: &str,
) -> Result<(StatusCode, Json<FollowResponse>), OidcError> {
    // Resolve the remote actor via WebFinger + actor fetch.
    let remote = delivery::resolve_remote_actor(handle, domain, &state.config.issuer()).await?;

    let caller = users::find_by_id(&state.pool, caller_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::server_error("Caller not found"))?;

    let caller_actor_url = format!("{}/users/{}", state.config.issuer(), caller.handle());
    let activity_id = format!(
        "{}/users/{}/follows/{}",
        state.config.issuer(),
        caller.handle(),
        Uuid::new_v4(),
    );

    // Build the Follow activity.
    let activity = Activity::follow(&activity_id, &caller_actor_url, &remote.actor_url);

    // Store the follow as "pending" (will be accepted/rejected by remote server).
    let follow = follows::send_follow_request(
        &state.pool,
        caller_id,
        // Use caller_id as a placeholder for the remote user (we don't have their UUID).
        // The ap_activity_id is what we use to match the Accept/Reject response.
        caller_id,
        Some(&activity_id),
    )
    .await
    .map_err(|e| OidcError::server_error(e.to_string()))?;

    // Deliver the signed Follow activity to the remote inbox.
    let activity_json = serde_json::to_value(&activity)
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    delivery::deliver_activity(state, &remote.inbox, &activity_json, &caller.handle()).await?;

    tracing::info!(
        caller = %caller.handle(),
        remote_actor = %remote.actor_url,
        "follow request sent to remote IdP (pending)"
    );

    Ok((StatusCode::CREATED, Json(FollowResponse {
        follow_id: follow.id,
        state: follow.state,
    })))
}

// ─── Unfollow ─────────────────────────────────────────────────────────────────

/// DELETE /api/follow/:address
#[tracing::instrument(skip_all, fields(address = %address))]
pub async fn delete_follow(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(address): Path<String>,
) -> Result<StatusCode, OidcError> {
    let caller_id = require_auth(&state, &headers).await?;

    let handle = handle_from_address(&address);
    let target = users::find_by_handle(&state.pool, handle)
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
        let domain = &state.config.domain;
        state.hub.send_to_user(&target.id, WsEvent::FollowRemoved(FollowPayload {
            follow_id: Uuid::nil(),
            address: caller.address(domain),
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
    pub follower_address: String,
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

    let domain = &state.config.domain;
    let mut summaries = Vec::with_capacity(rows.len());
    for row in rows {
        if let Some(follower) = users::find_by_id(&state.pool, row.follower_id)
            .await
            .map_err(|e| OidcError::server_error(e.to_string()))?
        {
            summaries.push(FollowRequestSummary {
                follow_id: row.id,
                follower_address: follower.address(domain),
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
        let domain = &state.config.domain;
        state.hub.send_to_user(&follow.follower_id, WsEvent::FollowAccepted(FollowPayload {
            follow_id: follow.id,
            address: caller.address(domain),
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
        let domain = &state.config.domain;
        state.hub.send_to_user(&follow.follower_id, WsEvent::FollowRejected(FollowPayload {
            follow_id: follow.id,
            address: caller.address(domain),
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
    let domain = &state.config.domain;
    let mut summaries = Vec::new();
    for id in ids {
        if let Some(u) = users::find_by_id(&state.pool, id)
            .await
            .map_err(|e| OidcError::server_error(e.to_string()))?
        {
            summaries.push(UserSummary { address: u.address(domain), username: u.username });
        }
    }
    Ok(Json(summaries))
}
