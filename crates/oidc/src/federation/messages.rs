//! REST API handlers for Direct Messages.
//!
//! All endpoints require a valid Bearer access token.

use axum::{
    extract::{Path, Query, State},
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
    /// Recipient's address, e.g. "@alice@idp.example.com" or "alice".
    pub recipient_address: String,
    pub content: String,
}

#[derive(Debug, Serialize)]
pub struct MessageResponse {
    pub id: Uuid,
    pub sender_actor_uri: String,
    pub recipient_actor_uri: String,
    pub content: String,
    pub activity_uri: String,
    pub federation_status: String,
    #[serde(with = "time::serde::rfc3339")]
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

    let sender_actor_uri = sender.actor_uri.as_deref()
        .ok_or_else(|| OidcError::server_error("Sender has no actor_uri"))?;

    // Parse recipient: "@username@domain" or "username@domain" or bare "username"
    let address = body.recipient_address.strip_prefix('@').unwrap_or(&body.recipient_address);
    let username = address.split('@').next().unwrap_or(address);

    let recipient = users::find_by_username(&state.pool, username)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::not_found("Recipient not found"))?;

    if recipient.id == sender_id {
        return Err(OidcError::invalid_request("Cannot send a DM to yourself"));
    }

    let recipient_actor_uri = recipient.actor_uri.as_deref()
        .ok_or_else(|| OidcError::server_error("Recipient has no actor_uri"))?;

    // Build an ActivityPub activity URI for federation traceability.
    let activity_uri = format!(
        "{}/users/{}/activities/{}",
        state.config.issuer(),
        sender.username,
        Uuid::new_v4(),
    );

    let msg = messages::create_message(
        &state.pool,
        sender_actor_uri,
        recipient_actor_uri,
        &body.content,
        &activity_uri,
    )
    .await
    .map_err(|e| OidcError::server_error(e.to_string()))?;

    let domain = &state.config.domain;

    // Push real-time event to connected WebSocket clients.
    let event = WsEvent::NewDm(DmPayload {
        message_id: msg.id,
        sender_address: sender.federated_address(domain),
        content: msg.content.clone(),
        created_at: msg.created_at,
    });

    // Publish to broker for durability
    if let Ok(json) = serde_json::to_string(&event) {
        let broker = state.broker.clone();
        let rid = recipient.id;
        let json_clone = json.clone();
        tokio::spawn(async move {
            if let Err(e) = broker.publish(rid, &json_clone).await {
                tracing::warn!(%rid, "broker publish failed: {e}");
            }
            if let Err(e) = broker.publish(sender_id, &json).await {
                tracing::warn!(%sender_id, "broker publish failed: {e}");
            }
        });
    }

    state.hub.send_to_user(&recipient.id, event.clone());
    state.hub.send_to_user(&sender_id, event);

    tracing::info!(
        sender = %sender.federated_address(domain),
        recipient = %recipient.federated_address(domain),
        "direct message sent"
    );

    Ok((StatusCode::CREATED, Json(MessageResponse {
        id: msg.id,
        sender_actor_uri: msg.sender_actor_uri,
        recipient_actor_uri: msg.recipient_actor_uri,
        content: msg.content,
        activity_uri: msg.activity_uri,
        federation_status: msg.federation_status,
        created_at: msg.created_at,
    })))
}

// ─── Get conversation ─────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ConversationQuery {
    /// Keyset cursor: created_at of the oldest message from the previous page (RFC 3339).
    pub cursor_created_at: Option<OffsetDateTime>,
    /// Keyset cursor: id of the oldest message from the previous page.
    pub cursor_id: Option<Uuid>,
    /// Page size (default 50, max 100).
    pub limit: Option<i64>,
}

/// GET /api/dm/:address?cursor_created_at=...&cursor_id=...&limit=50
/// Conversation with a specific user, newest-first with keyset pagination.
#[tracing::instrument(skip_all, fields(address = %address))]
pub async fn get_conversation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(address): Path<String>,
    Query(query): Query<ConversationQuery>,
) -> Result<Json<Vec<MessageResponse>>, OidcError> {
    let caller_id = require_auth(&state, &headers).await?;

    let caller = users::find_by_id(&state.pool, caller_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::server_error("Caller not found"))?;

    let caller_actor_uri = caller.actor_uri.as_deref()
        .ok_or_else(|| OidcError::server_error("Caller has no actor_uri"))?;

    // Parse address: "@username@domain" or "username@domain" or bare "username"
    let addr = address.strip_prefix('@').unwrap_or(&address);
    let username = addr.split('@').next().unwrap_or(addr);

    let other = users::find_by_username(&state.pool, username)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::not_found("User not found"))?;

    let other_actor_uri = other.actor_uri.as_deref()
        .ok_or_else(|| OidcError::server_error("User has no actor_uri"))?;

    let limit = query.limit.unwrap_or(50).min(100);

    let msgs = match (query.cursor_created_at, query.cursor_id) {
        (Some(cursor_ts), Some(cursor_id)) => {
            messages::get_conversation_before(
                &state.pool,
                caller_actor_uri,
                other_actor_uri,
                cursor_ts,
                cursor_id,
                limit,
            )
            .await
        }
        _ => {
            messages::get_conversation(&state.pool, caller_actor_uri, other_actor_uri, limit).await
        }
    }
    .map_err(|e| OidcError::server_error(e.to_string()))?;

    let responses = msgs
        .into_iter()
        .map(|m| MessageResponse {
            id: m.id,
            sender_actor_uri: m.sender_actor_uri,
            recipient_actor_uri: m.recipient_actor_uri,
            content: m.content,
            activity_uri: m.activity_uri,
            federation_status: m.federation_status,
            created_at: m.created_at,
        })
        .collect();

    Ok(Json(responses))
}

// ─── List conversations ───────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct ConversationListItem {
    pub other_actor_uri: String,
    #[serde(with = "time::serde::rfc3339")]
    pub last_message_at: OffsetDateTime,
}

/// GET /api/dm — list all DM conversations, most-recent first
#[tracing::instrument(skip_all)]
pub async fn list_conversations(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<ConversationListItem>>, OidcError> {
    let caller_id = require_auth(&state, &headers).await?;

    let caller = users::find_by_id(&state.pool, caller_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::server_error("Caller not found"))?;

    let caller_actor_uri = caller.actor_uri.as_deref()
        .ok_or_else(|| OidcError::server_error("Caller has no actor_uri"))?;

    let summaries = messages::list_conversations(&state.pool, caller_actor_uri)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    let items = summaries
        .into_iter()
        .map(|s| ConversationListItem {
            other_actor_uri: s.other_actor_uri,
            last_message_at: s.last_message_at,
        })
        .collect();

    Ok(Json(items))
}
