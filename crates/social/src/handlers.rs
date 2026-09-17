//! REST API handlers for the friendship system (friend request / unfriend / accept).
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
use idp_db::repos::{conversations, friendships, remote_actors, users};
use idp_federation::auth::require_auth;
use idp_federation::delivery;
use idp_realtime::{FriendshipPayload, WsEvent};
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

    let limit = params.limit.min(50).max(1);
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

// ─── Send friend request ─────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct FriendRequest {
    /// Federated address, e.g. `"@alice@idp.example.com"` or `"alice@idp.example.com"`.
    pub address: String,
}

#[derive(Debug, Serialize)]
pub struct FriendResponse {
    pub friendship_id: Uuid,
    pub status: String,
}

/// POST /api/friends/request
#[tracing::instrument(skip_all)]
pub async fn post_friend_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<FriendRequest>,
) -> Result<(StatusCode, Json<FriendResponse>), OidcError> {
    let caller_id = require_auth(&state, &headers).await?;

    // Strip leading '@' if present, then parse "username@domain".
    let address = body.address.strip_prefix('@').unwrap_or(&body.address);
    if let Some((username, domain)) = address.split_once('@') {
        if domain == state.config.domain {
            return friend_request_local(&state, caller_id, username).await;
        }
        return friend_request_remote(&state, caller_id, username, domain).await;
    }

    // Bare username — treat as local.
    friend_request_local(&state, caller_id, address).await
}

/// Send a friend request to a local user. Mirrors the cross-IdP shape:
/// both rows land in `pending`, the target gets a single `FriendRequest`
/// WS event, and the friendship only transitions to `accepted` when the
/// target POSTs `/api/friends/:id/accept`.
async fn friend_request_local(
    state: &AppState,
    caller_id: Uuid,
    username: &str,
) -> Result<(StatusCode, Json<FriendResponse>), OidcError> {
    let target = users::find_by_username(&state.pool, username)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::not_found("User not found"))?;

    if target.id == caller_id {
        return Err(OidcError::invalid_request("Cannot friend yourself"));
    }

    let target_actor_uri = target
        .actor_uri
        .as_deref()
        .ok_or_else(|| OidcError::server_error("Target user has no actor_uri"))?;

    let caller = users::find_by_id(&state.pool, caller_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::server_error("Caller not found"))?;

    let caller_actor_uri = caller
        .actor_uri
        .as_deref()
        .ok_or_else(|| OidcError::server_error("Caller has no actor_uri"))?;

    // Both rows persist as `pending`. The caller's row is the placeholder
    // for "I asked them"; the target's row is what `get_pending_requests`
    // and `accept_friendship` operate on.
    let caller_row = friendships::create_friendship(
        &state.pool,
        caller_id,
        target_actor_uri,
        target.avatar_url.as_deref(),
    )
    .await
    .map_err(|e| OidcError::server_error(e.to_string()))?;

    let target_row = friendships::create_friendship(
        &state.pool,
        target.id,
        caller_actor_uri,
        caller.avatar_url.as_deref(),
    )
    .await
    .map_err(|e| OidcError::server_error(e.to_string()))?;

    // Single notification: the target sees an incoming request. The DM
    // conversation is minted later inside `accept_friendship`, so
    // `conversation_id` is None here.
    state.hub.send_to_user(
        &target.id,
        WsEvent::FriendRequest(FriendshipPayload {
            friendship_id: target_row.id,
            actor_uri: caller_actor_uri.to_string(),
            username: caller.username.clone(),
            display_name: caller.display_name.clone(),
            conversation_id: None,
        }),
    );

    tracing::info!(caller = %caller_id, target = %target.id, "friend request sent (local, pending)");

    Ok((
        StatusCode::CREATED,
        Json(FriendResponse {
            friendship_id: caller_row.id,
            status: caller_row.status,
        }),
    ))
}

/// Send a friend request to a remote user via ActivityPub.
async fn friend_request_remote(
    state: &AppState,
    caller_id: Uuid,
    username: &str,
    domain: &str,
) -> Result<(StatusCode, Json<FriendResponse>), OidcError> {
    // Resolve the remote actor via WebFinger + actor fetch.
    let remote = delivery::resolve_remote_actor(username, domain, &state.config.issuer()).await?;

    // Cache the remote actor.
    remote_actors::upsert(
        &state.pool,
        &remote.actor_url,
        Some(&remote.inbox),
        domain,
        remote.display_name.as_deref(),
        remote.avatar_url.as_deref(),
    )
    .await
    .map_err(|e| OidcError::server_error(e.to_string()))?;

    let caller = users::find_by_id(&state.pool, caller_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::server_error("Caller not found"))?;

    let caller_actor_uri = caller
        .actor_uri
        .as_deref()
        .ok_or_else(|| OidcError::server_error("Caller has no actor_uri"))?;

    let activity_id = format!("{}/friendships/{}", caller_actor_uri, Uuid::new_v4(),);

    // Build the Follow activity (AP Follow = friend request).
    let activity = Activity::follow(&activity_id, caller_actor_uri, &remote.actor_url);

    // Create the friendship as "pending".
    let friendship = friendships::create_friendship(
        &state.pool,
        caller_id,
        &remote.actor_url,
        remote.avatar_url.as_deref(),
    )
    .await
    .map_err(|e| OidcError::server_error(e.to_string()))?;

    // Deliver the signed Follow activity to the remote inbox.
    let activity_json =
        serde_json::to_value(&activity).map_err(|e| OidcError::server_error(e.to_string()))?;

    delivery::deliver_activity(state, &remote.inbox, &activity_json, &caller.username).await?;

    tracing::info!(
        caller = %caller.username,
        remote_actor = %remote.actor_url,
        "friend request sent to remote IdP (pending)"
    );

    Ok((
        StatusCode::CREATED,
        Json(FriendResponse {
            friendship_id: friendship.id,
            status: friendship.status,
        }),
    ))
}

// ─── Unfriend ────────────────────────────────────────────────────────────────

/// DELETE /api/friends/{friend_actor_uri}
/// The actor_uri is URL-encoded in the path.
#[tracing::instrument(skip_all)]
pub async fn delete_friendship(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(friend_actor_uri): Path<String>,
) -> Result<StatusCode, OidcError> {
    let caller_id = require_auth(&state, &headers).await?;

    // URL-decode the actor_uri from the path.
    let friend_actor_uri = urlencoding::decode(&friend_actor_uri)
        .map_err(|_| OidcError::invalid_request("Invalid actor URI encoding"))?;

    friendships::delete_friendship(&state.pool, caller_id, &friend_actor_uri)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    // If the friend is local, also remove the reciprocal friendship.
    if let Some(friend_user) = users::find_by_actor_uri(&state.pool, &friend_actor_uri)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
    {
        let caller = users::find_by_id(&state.pool, caller_id)
            .await
            .map_err(|e| OidcError::server_error(e.to_string()))?;

        if let Some(caller) = caller {
            if let Some(caller_uri) = &caller.actor_uri {
                friendships::delete_friendship(&state.pool, friend_user.id, caller_uri)
                    .await
                    .map_err(|e| OidcError::server_error(e.to_string()))?;
            }

            // Notify the friend.
            state.hub.send_to_user(
                &friend_user.id,
                WsEvent::FriendRemoved(FriendshipPayload {
                    friendship_id: Uuid::nil(),
                    actor_uri: caller.actor_uri.unwrap_or_default(),
                    username: caller.username,
                    display_name: caller.display_name,
                    conversation_id: None,
                }),
            );
        }
    }

    // Drop the friend from batch presence polling. Best-effort — if
    // they were never registered (e.g. local friend), `unregister_friend`
    // short-circuits via the `starts_with(local_issuer)` guard.
    if let Some(registry) = &state.remote_registry {
        registry.unregister_friend(&friend_actor_uri, &state.config.issuer());
    }

    tracing::info!(caller = %caller_id, friend = %friend_actor_uri, "unfriended");
    Ok(StatusCode::NO_CONTENT)
}

// ─── Incoming friend requests ────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct FriendRequestSummary {
    pub friendship_id: Uuid,
    pub actor_uri: String,
    pub username: String,
    pub display_name: Option<String>,
    pub status: String,
}

/// GET /api/friends/incoming — pending friend requests aimed at me
#[tracing::instrument(skip_all)]
pub async fn get_incoming_requests(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<FriendRequestSummary>>, OidcError> {
    let caller_id = require_auth(&state, &headers).await?;

    let rows = friendships::get_pending_requests(&state.pool, caller_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    let mut summaries = Vec::with_capacity(rows.len());
    for row in rows {
        // Try to resolve the friend's username from local users or remote_actors cache.
        let (username, display_name) = resolve_actor_name(&state, &row.friend_actor_uri).await;

        summaries.push(FriendRequestSummary {
            friendship_id: row.id,
            actor_uri: row.friend_actor_uri,
            username,
            display_name,
            status: row.status,
        });
    }

    Ok(Json(summaries))
}

// ─── Accept friend request ───────────────────────────────────────────────────

/// POST /api/friends/{friendship_id}/accept
#[tracing::instrument(skip_all, fields(friendship_id = %friendship_id))]
pub async fn accept_friendship(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(friendship_id): Path<Uuid>,
) -> Result<StatusCode, OidcError> {
    let caller_id = require_auth(&state, &headers).await?;

    let friendship = friendships::find_by_id(&state.pool, friendship_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::not_found("Friend request not found"))?;

    // Caller must be the owner of this friendship row.
    if friendship.owner_user_id != caller_id {
        return Err(OidcError::invalid_request(
            "Not authorised to accept this request",
        ));
    }

    friendships::set_status(&state.pool, friendship.id, "accepted")
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    let caller = users::find_by_id(&state.pool, caller_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::server_error("Caller not found"))?;

    let caller_actor_uri = caller
        .actor_uri
        .as_deref()
        .ok_or_else(|| OidcError::server_error("Caller has no actor_uri"))?;

    // Create the DM conversation in the same logical transaction as
    // the friendship-accept. The conversation_id decided here is the
    // one both clients will use forever — no more per-first-message
    // UUID minting on the client side. Cross-IdP: we surface it in
    // the outbound AP `Accept{Follow}` envelope so the peer's IdP
    // creates its row with the same id.
    let (conversation_id, _created) = conversations::get_or_create_dm(
        &state.pool,
        caller_actor_uri,
        &friendship.friend_actor_uri,
    )
    .await
    .map_err(|e| OidcError::server_error(e.to_string()))?;

    // Notify the requester.
    if let Some(friend_user) = users::find_by_actor_uri(&state.pool, &friendship.friend_actor_uri)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
    {
        // Local friend — also flip the requester's reverse row. Both rows
        // live in this DB (we inserted them together in `friend_request_local`
        // / `handle_follow`), so the friend list query (`status='accepted'`)
        // only finds the friendship after we update both sides here.
        if let Some(reverse) =
            friendships::find_by_owner_and_uri(&state.pool, friend_user.id, caller_actor_uri)
                .await
                .map_err(|e| OidcError::server_error(e.to_string()))?
        {
            friendships::set_status(&state.pool, reverse.id, "accepted")
                .await
                .map_err(|e| OidcError::server_error(e.to_string()))?;
        } else {
            tracing::warn!(
                friend = %friendship.friend_actor_uri,
                "local accept with no reverse friendship row — friend list will look one-sided"
            );
        }

        state.hub.send_to_user(
            &friend_user.id,
            WsEvent::FriendAccepted(FriendshipPayload {
                friendship_id: friendship.id,
                actor_uri: caller_actor_uri.to_string(),
                username: caller.username.clone(),
                display_name: caller.display_name.clone(),
                conversation_id: Some(conversation_id),
            }),
        );
    } else {
        // Remote friend — deliver an AP Accept so their IdP updates the friendship.
        let remote = remote_actors::find_by_actor_uri(&state.pool, &friendship.friend_actor_uri)
            .await
            .map_err(|e| OidcError::server_error(e.to_string()))?;

        if let Some(remote) = remote {
            let inbox_url = format!("{}/inbox", remote.actor_uri);

            let accept_id = format!("{}/accepts/{}", caller_actor_uri, Uuid::new_v4());
            let follow_activity = Activity::follow(
                &format!("{}/follows/{}", &friendship.friend_actor_uri, friendship.id),
                &friendship.friend_actor_uri,
                caller_actor_uri,
            );
            let follow_value = serde_json::to_value(&follow_activity)
                .map_err(|e| OidcError::server_error(e.to_string()))?;
            let accept = Activity::accept(&accept_id, caller_actor_uri, follow_value);

            let mut activity_json = serde_json::to_value(&accept)
                .map_err(|e| OidcError::server_error(e.to_string()))?;
            // Custom field: the conversation_id we just created locally.
            // Peer IdP reads this in `handle_accept` and creates the
            // corresponding row with the same id, so both sides agree
            // on `conversations.id` from the first moment the DM
            // exists. Non-standard JSON-LD but harmless to outside
            // implementations — they ignore unknown fields.
            if let Some(obj) = activity_json.as_object_mut() {
                obj.insert(
                    "conversationId".to_string(),
                    serde_json::Value::String(conversation_id.to_string()),
                );
            }

            delivery::deliver_activity(&state, &inbox_url, &activity_json, &caller.username)
                .await?;

            tracing::info!(
                friend = %friendship.friend_actor_uri,
                %conversation_id,
                "AP Accept delivered to remote IdP"
            );
        }
    }

    // Register the friend for batch presence polling so their online
    // state appears in this IdP's local presence store within one poll
    // interval. No-op for local friends — their presence flows through
    // the local WS hub already.
    if let Some(registry) = &state.remote_registry {
        registry.register_friend(&friendship.friend_actor_uri, &state.config.issuer());
    }

    tracing::info!(friendship_id = %friendship_id, %conversation_id, "friend request accepted");
    Ok(StatusCode::NO_CONTENT)
}

// ─── Reject (delete) friend request ─────────────────────────────────────────

/// DELETE /api/friends/{friendship_id}/reject
#[tracing::instrument(skip_all, fields(friendship_id = %friendship_id))]
pub async fn reject_friendship(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(friendship_id): Path<Uuid>,
) -> Result<StatusCode, OidcError> {
    let caller_id = require_auth(&state, &headers).await?;

    let friendship = friendships::find_by_id(&state.pool, friendship_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::not_found("Friend request not found"))?;

    if friendship.owner_user_id != caller_id {
        return Err(OidcError::invalid_request(
            "Not authorised to reject this request",
        ));
    }

    // Rejecting = deleting the friendship row (no "rejected" state in the new model).
    friendships::delete_friendship(&state.pool, caller_id, &friendship.friend_actor_uri)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    tracing::info!(friendship_id = %friendship_id, "friend request rejected (deleted)");
    Ok(StatusCode::NO_CONTENT)
}

// ─── Friends list ────────────────────────────────────────────────────────────

/// GET /api/friends — my accepted friends (joined across local users and remote actors)
#[tracing::instrument(skip_all)]
pub async fn get_friends(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<idp_db::models::FriendListEntry>>, OidcError> {
    let caller_id = require_auth(&state, &headers).await?;

    let friends = friendships::get_friends(&state.pool, caller_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    Ok(Json(friends))
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Resolve an actor_uri to a (username, display_name) pair.
/// Checks local users first, then the remote_actors cache.
async fn resolve_actor_name(state: &AppState, actor_uri: &str) -> (String, Option<String>) {
    if let Ok(Some(user)) = users::find_by_actor_uri(&state.pool, actor_uri).await {
        return (user.username, user.display_name);
    }
    let display_name = remote_actors::find_by_actor_uri(&state.pool, actor_uri)
        .await
        .ok()
        .flatten()
        .and_then(|ra| ra.display_name);
    let username = actor_uri
        .rsplit('/')
        .next()
        .unwrap_or("unknown")
        .to_string();
    (username, display_name)
}
