//! POST /users/:handle/inbox
//!
//! Receives ActivityPub activities from remote and local servers.
//! Supported activities:
//!   - Follow       → creates a pending follow, auto-accepts for local users
//!   - Accept{Follow} → marks a follow as accepted
//!   - Reject{Follow} → marks a follow as rejected
//!   - Undo{Follow}   → deletes the follow
//!   - Create{Note}   → stores a direct message

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde_json::Value;
use uuid::Uuid;

use idp_db::repos::{follows, messages, users};

use crate::ws::events::{DmPayload, FollowPayload, WsEvent};
use crate::{AppState, OidcError};

/// POST /users/:handle/inbox
#[tracing::instrument(skip_all, fields(handle = %handle))]
pub async fn post_inbox(
    State(state): State<AppState>,
    Path(handle): Path<String>,
    _headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<StatusCode, OidcError> {
    // 1. Resolve the inbox owner.
    let recipient = users::find_by_handle(&state.pool, &handle)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::not_found("User not found"))?;

    let activity_type = body
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    tracing::debug!(
        recipient = %recipient.handle(),
        activity_type = %activity_type,
        "inbox activity received"
    );

    match activity_type.as_str() {
        "Follow" => handle_follow(&state, &body, recipient.id).await?,
        "Accept" => handle_accept(&state, &body).await?,
        "Reject" => handle_reject(&state, &body).await?,
        "Undo" => handle_undo(&state, &body, recipient.id).await?,
        "Create" => handle_create(&state, &body, recipient.id).await?,
        other => {
            tracing::warn!(activity_type = %other, "unhandled activity type in inbox");
        }
    }

    Ok(StatusCode::ACCEPTED)
}

// ─── Follow ───────────────────────────────────────────────────────────────────

async fn handle_follow(
    state: &AppState,
    body: &Value,
    recipient_id: Uuid,
) -> Result<(), OidcError> {
    let actor_url = body
        .get("actor")
        .and_then(|v| v.as_str())
        .ok_or_else(|| OidcError::invalid_request("Follow missing actor field"))?;

    let activity_id = body.get("id").and_then(|v| v.as_str());

    // For local-origin actors (same domain), resolve by actor URL → user UUID.
    let base = state.config.issuer();
    if let Some(follower_id) = local_actor_id(actor_url, &base, &state.pool).await {
        // Local-to-local follow: create the row and auto-accept.
        let follow = follows::send_follow_request(
            &state.pool,
            follower_id,
            recipient_id,
            activity_id,
        )
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

        follows::set_follow_state(&state.pool, follow.id, "accepted")
            .await
            .map_err(|e| OidcError::server_error(e.to_string()))?;

        // Push real-time notification to inbox owner.
        if let Ok(Some(follower)) = users::find_by_id(&state.pool, follower_id).await {
            let payload = FollowPayload {
                follow_id: follow.id,
                handle: follower.handle(),
                username: follower.username,
            };
            state.hub.send_to_user(&recipient_id, WsEvent::FollowRequest(payload.clone()));
            state.hub.send_to_user(&recipient_id, WsEvent::FollowAccepted(payload));
        }

        tracing::info!(
            follower_id = %follower_id,
            following_id = %recipient_id,
            "local follow auto-accepted"
        );
    } else {
        // Remote actor — store as pending; a human Accept/Reject is needed
        // (or we could auto-accept here too, keeping it simple for now).
        tracing::info!(actor = %actor_url, "remote follow stored as pending (not yet supported)");
    }

    Ok(())
}

// ─── Accept ───────────────────────────────────────────────────────────────────

async fn handle_accept(state: &AppState, body: &Value) -> Result<(), OidcError> {
    // The `object` field should be the original Follow activity or its ID.
    let follow_activity_id = extract_object_id(body);

    if let Some(ap_id) = follow_activity_id {
        // Find the follow row by its ap_activity_id.
        let result = sqlx::query_as::<_, idp_db::models::Follow>(
            "SELECT * FROM follows WHERE ap_activity_id = $1",
        )
        .bind(&ap_id)
        .fetch_optional(&state.pool)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

        if let Some(follow) = result {
            follows::set_follow_state(&state.pool, follow.id, "accepted")
                .await
                .map_err(|e| OidcError::server_error(e.to_string()))?;

            // Notify the follower their request was accepted.
            if let Ok(Some(target)) = users::find_by_id(&state.pool, follow.following_id).await {
                state.hub.send_to_user(&follow.follower_id, WsEvent::FollowAccepted(FollowPayload {
                    follow_id: follow.id,
                    handle: target.handle(),
                    username: target.username,
                }));
            }

            tracing::info!(follow_id = %follow.id, "follow accepted via AP");
        }
    }
    Ok(())
}

// ─── Reject ───────────────────────────────────────────────────────────────────

async fn handle_reject(state: &AppState, body: &Value) -> Result<(), OidcError> {
    let follow_activity_id = extract_object_id(body);

    if let Some(ap_id) = follow_activity_id {
        let result = sqlx::query_as::<_, idp_db::models::Follow>(
            "SELECT * FROM follows WHERE ap_activity_id = $1",
        )
        .bind(&ap_id)
        .fetch_optional(&state.pool)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

        if let Some(follow) = result {
            follows::set_follow_state(&state.pool, follow.id, "rejected")
                .await
                .map_err(|e| OidcError::server_error(e.to_string()))?;

            // Notify the follower their request was rejected.
            if let Ok(Some(target)) = users::find_by_id(&state.pool, follow.following_id).await {
                state.hub.send_to_user(&follow.follower_id, WsEvent::FollowRejected(FollowPayload {
                    follow_id: follow.id,
                    handle: target.handle(),
                    username: target.username,
                }));
            }

            tracing::info!(follow_id = %follow.id, "follow rejected via AP");
        }
    }
    Ok(())
}

// ─── Undo{Follow} ─────────────────────────────────────────────────────────────

async fn handle_undo(
    state: &AppState,
    body: &Value,
    recipient_id: Uuid,
) -> Result<(), OidcError> {
    let obj = body.get("object");
    // We only handle Undo{Follow}.
    let obj_type = obj
        .and_then(|o| o.get("type"))
        .and_then(|t| t.as_str())
        .unwrap_or("");

    if obj_type != "Follow" {
        return Ok(());
    }

    let actor_url = body
        .get("actor")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let base = state.config.issuer();
    if let Some(follower_id) = local_actor_id(actor_url, &base, &state.pool).await {
        follows::delete_follow(&state.pool, follower_id, recipient_id)
            .await
            .map_err(|e| OidcError::server_error(e.to_string()))?;

        // Notify recipient that they lost a follower.
        if let Ok(Some(follower)) = users::find_by_id(&state.pool, follower_id).await {
            state.hub.send_to_user(&recipient_id, WsEvent::FollowRemoved(FollowPayload {
                follow_id: Uuid::nil(),
                handle: follower.handle(),
                username: follower.username,
            }));
        }

        tracing::info!(follower_id = %follower_id, following_id = %recipient_id, "unfollowed via AP Undo");
    }
    Ok(())
}

// ─── Create{Note} (Direct Message) ───────────────────────────────────────────

async fn handle_create(
    state: &AppState,
    body: &Value,
    recipient_id: Uuid,
) -> Result<(), OidcError> {
    let obj = match body.get("object") {
        Some(o) => o,
        None => return Ok(()),
    };

    let obj_type = obj
        .get("type")
        .and_then(|t| t.as_str())
        .unwrap_or("");

    if obj_type != "Note" {
        return Ok(());
    }

    let content = obj
        .get("content")
        .and_then(|c| c.as_str())
        .unwrap_or("")
        .to_string();

    let note_id = obj.get("id").and_then(|v| v.as_str());
    let actor_url = body.get("actor").and_then(|v| v.as_str()).unwrap_or("");

    let base = state.config.issuer();
    if let Some(sender_id) = local_actor_id(actor_url, &base, &state.pool).await {
        let msg = messages::create_message(&state.pool, sender_id, recipient_id, &content, note_id)
            .await
            .map_err(|e| OidcError::server_error(e.to_string()))?;

        // Push real-time DM notification.
        if let Ok(Some(sender)) = users::find_by_id(&state.pool, sender_id).await {
            let event = WsEvent::NewDm(DmPayload {
                message_id: msg.id,
                sender_handle: sender.handle(),
                content: msg.content,
                created_at: msg.created_at,
            });
            state.hub.send_to_user(&recipient_id, event.clone());
            state.hub.send_to_user(&sender_id, event);
        }

        tracing::info!(sender_id = %sender_id, recipient_id = %recipient_id, "DM stored via AP inbox");
    }
    Ok(())
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Try to resolve a local actor URL (e.g. `https://base/users/alex-7G4K`) to a UUID.
async fn local_actor_id(actor_url: &str, base: &str, pool: &sqlx::PgPool) -> Option<Uuid> {
    let prefix = format!("{}/users/", base);
    let handle = actor_url.strip_prefix(&prefix)?;
    users::find_by_handle(pool, handle)
        .await
        .ok()
        .flatten()
        .map(|u| u.id)
}

/// Extract the `id` field from the `object` in an activity (string or nested object).
fn extract_object_id(body: &Value) -> Option<String> {
    let obj = body.get("object")?;
    if let Some(s) = obj.as_str() {
        return Some(s.to_string());
    }
    obj.get("id").and_then(|v| v.as_str()).map(|s| s.to_string())
}
