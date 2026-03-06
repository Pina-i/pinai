//! REST API handlers for Direct Messages.
//!
//! All endpoints require a valid Bearer access token.

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use idp_db::repos::{messages, users};

use crate::ws::events::{DmPayload, WsEvent};
use crate::{AppState, OidcError};
use super::auth::require_auth;

// ─── Send a DM ────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct SendMessageRequest {
    /// Recipient's full handle, e.g. "alice-A1B2".
    pub recipient_handle: String,
    pub content: String,
}

#[derive(Debug, Serialize)]
pub struct MessageResponse {
    pub id: Uuid,
    pub sender_handle: String,
    pub recipient_handle: String,
    pub content: String,
    pub created_at: OffsetDateTime,
}

/// POST /api/dm
#[tracing::instrument(skip_all)]
pub async fn send_message(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<SendMessageRequest>,
) -> Result<(StatusCode, Json<MessageResponse>), OidcError> {
    let sender_id = require_auth(&state, &headers).await?;

    if body.content.is_empty() {
        return Err(OidcError::invalid_request("Message content cannot be empty"));
    }
    if body.content.len() > 4096 {
        return Err(OidcError::invalid_request("Message content too long (max 4096 chars)"));
    }

    let sender = users::find_by_id(&state.pool, sender_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::server_error("Sender not found"))?;

    let recipient = users::find_by_handle(&state.pool, &body.recipient_handle)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::not_found("Recipient not found"))?;

    if recipient.id == sender_id {
        return Err(OidcError::invalid_request("Cannot send a DM to yourself"));
    }

    // Build an AP Note ID for federation traceability.
    let note_id = format!(
        "{}/users/{}/notes/{}",
        state.config.issuer(),
        sender.handle(),
        Uuid::new_v4(),
    );

    let msg = messages::create_message(
        &state.pool,
        sender_id,
        recipient.id,
        &body.content,
        Some(&note_id),
    )
    .await
    .map_err(|e| OidcError::server_error(e.to_string()))?;

    // Push real-time event to connected WebSocket clients.
    let event = WsEvent::NewDm(DmPayload {
        message_id: msg.id,
        sender_handle: sender.handle(),
        content: msg.content.clone(),
        created_at: msg.created_at,
    });
    state.hub.send_to_user(&recipient.id, event.clone());
    state.hub.send_to_user(&sender_id, event);

    tracing::info!(
        sender = %sender.handle(),
        recipient = %recipient.handle(),
        "direct message sent"
    );

    Ok((StatusCode::CREATED, Json(MessageResponse {
        id: msg.id,
        sender_handle: sender.handle(),
        recipient_handle: recipient.handle(),
        content: msg.content,
        created_at: msg.created_at,
    })))
}

// ─── Get conversation ─────────────────────────────────────────────────────────

/// GET /api/dm/:handle — messages with a specific user (oldest-first, last 100)
#[tracing::instrument(skip_all, fields(handle = %handle))]
pub async fn get_conversation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(handle): Path<String>,
) -> Result<Json<Vec<MessageResponse>>, OidcError> {
    let caller_id = require_auth(&state, &headers).await?;

    let caller = users::find_by_id(&state.pool, caller_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::server_error("Caller not found"))?;

    let other = users::find_by_handle(&state.pool, &handle)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::not_found("User not found"))?;

    let msgs = messages::get_conversation(&state.pool, caller_id, other.id, 100)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    let responses = msgs
        .into_iter()
        .map(|m| {
            let (sender_handle, recipient_handle) = if m.sender_id == caller_id {
                (caller.handle(), other.handle())
            } else {
                (other.handle(), caller.handle())
            };
            MessageResponse {
                id: m.id,
                sender_handle,
                recipient_handle,
                content: m.content,
                created_at: m.created_at,
            }
        })
        .collect();

    Ok(Json(responses))
}

// ─── List conversations ───────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct ConversationListItem {
    pub other_handle: String,
    pub other_username: String,
    pub last_message_at: OffsetDateTime,
}

/// GET /api/dm — list all DM conversations, most-recent first
#[tracing::instrument(skip_all)]
pub async fn list_conversations(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<ConversationListItem>>, OidcError> {
    let caller_id = require_auth(&state, &headers).await?;

    let summaries = messages::list_conversations(&state.pool, caller_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    let mut items = Vec::with_capacity(summaries.len());
    for s in summaries {
        if let Some(other) = users::find_by_id(&state.pool, s.other_user_id)
            .await
            .map_err(|e| OidcError::server_error(e.to_string()))?
        {
            items.push(ConversationListItem {
                other_handle: other.handle(),
                other_username: other.username,
                last_message_at: s.last_message_at,
            });
        }
    }

    Ok(Json(items))
}
