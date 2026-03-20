//! REST API handlers for Direct Messages, reactions, and replies.
//!
//! All endpoints require a valid Bearer access token.

use std::collections::HashMap;

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use idp_db::repos::{dm_reads, messages, reactions, remote_actors, users};

use crate::federation::delivery;
use crate::ws::events::{DmPayload, ReactionPayload, WsEvent};
use crate::{AppState, OidcError};
use super::auth::require_auth;

/// Look up the display name for an actor URI.
/// Checks local users first, then the remote actors cache.
/// For local users, falls back to `username` if `display_name` is unset.
async fn display_name_for_actor(pool: &PgPool, actor_uri: &str) -> Option<String> {
    if let Ok(Some(user)) = users::find_by_actor_uri(pool, actor_uri).await {
        return Some(user.display_name.unwrap_or(user.username));
    }
    if let Ok(Some(ra)) = remote_actors::find_by_actor_uri(pool, actor_uri).await {
        return ra.display_name;
    }
    None
}

// ─── Reaction group (shared response type) ───────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct ReactionGroup {
    pub emoji: String,
    pub count: i64,
    pub reacted_by_me: bool,
}

// ─── Send a DM ────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct SendMessageRequest {
    /// Recipient's address, e.g. "@alice@idp.example.com" or "alice".
    pub recipient_address: String,
    pub content: String,
    /// Optional: reply to an existing message.
    pub reply_to_id: Option<Uuid>,
}

#[derive(Debug, Serialize)]
pub struct MessageResponse {
    pub id: Uuid,
    pub sender_actor_uri: String,
    pub sender_display_name: Option<String>,
    pub recipient_actor_uri: String,
    pub content: String,
    pub activity_uri: String,
    pub federation_status: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_to_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_to_content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_to_sender: Option<String>,
    pub reactions: Vec<ReactionGroup>,
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

    let sender_display_name: Option<String> =
        Some(sender.display_name.clone().unwrap_or_else(|| sender.username.clone()));

    // If this is a reply, validate the parent message exists.
    let mut reply_to_content: Option<String> = None;
    let mut reply_to_sender: Option<String> = None;
    let mut parent_activity_uri: Option<String> = None;
    if let Some(parent_id) = body.reply_to_id {
        let parent = messages::find_by_id(&state.pool, parent_id)
            .await
            .map_err(|e| OidcError::server_error(e.to_string()))?
            .ok_or_else(|| OidcError::not_found("Parent message not found"))?;
        reply_to_content = Some(parent.content.clone());
        reply_to_sender = Some(parent.sender_actor_uri.clone());
        parent_activity_uri = Some(parent.activity_uri.clone());
    }

    // Parse recipient: "@username@domain" or "username@domain" or bare "username"
    let address = body.recipient_address.strip_prefix('@').unwrap_or(&body.recipient_address);
    let mut parts = address.splitn(2, '@');
    let username = parts.next().unwrap_or(address);
    let domain_opt = parts.next();

    let is_remote = domain_opt.map_or(false, |d| d != state.config.domain);

    let activity_uri = format!(
        "{}/users/{}/activities/{}",
        state.config.issuer(),
        sender.username,
        Uuid::new_v4(),
    );
    let local_domain = state.config.domain.clone();

    if is_remote {
        let domain = domain_opt.unwrap();
        let issuer = state.config.issuer();
        let scheme = if issuer.starts_with("https") { "https" } else { "http" };
        let guessed_actor_uri = format!("{}://{}/users/{}", scheme, domain, username);

        // Cache-first lookup
        let (recipient_actor_uri, inbox_url) =
            match remote_actors::find_by_actor_uri(&state.pool, &guessed_actor_uri).await {
                Ok(Some(ra)) if ra.inbox_url.is_some() => (ra.actor_uri, ra.inbox_url.unwrap()),
                _ => {
                    let ra = delivery::resolve_remote_actor(username, domain, &issuer).await?;
                    let inbox = ra.inbox.clone();
                    let actor_url = ra.actor_url.clone();
                    let pool = state.pool.clone();
                    let domain_owned = domain.to_string();
                    let display = ra.display_name.clone();
                    let avatar = ra.avatar_url.clone();
                    let inbox_clone = inbox.clone();
                    tokio::spawn(async move {
                        if let Err(e) = remote_actors::upsert(
                            &pool,
                            &actor_url,
                            Some(&inbox_clone),
                            &domain_owned,
                            display.as_deref(),
                            avatar.as_deref(),
                        )
                        .await
                        {
                            tracing::warn!("failed to cache remote actor: {e}");
                        }
                    });
                    (ra.actor_url, inbox)
                }
            };

        let msg = messages::create_message(
            &state.pool,
            sender_actor_uri,
            &recipient_actor_uri,
            &body.content,
            &activity_uri,
            body.reply_to_id,
        )
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

        // Build and deliver Create{Note} in background
        let note = if let Some(ref parent_uri) = parent_activity_uri {
            activitypub::Note::direct_reply(
                &activity_uri,
                sender_actor_uri,
                &recipient_actor_uri,
                &body.content,
                parent_uri,
            )
        } else {
            activitypub::Note::direct(
                &activity_uri,
                sender_actor_uri,
                &recipient_actor_uri,
                &body.content,
            )
        };
        let activity = activitypub::create_note_activity(
            &activity_uri,
            sender_actor_uri,
            &recipient_actor_uri,
            note,
        );
        if let Ok(activity_value) = serde_json::to_value(&activity) {
            let state_clone = state.clone();
            let sender_username = sender.username.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    delivery::deliver_activity(&state_clone, &inbox_url, &activity_value, &sender_username)
                        .await
                {
                    tracing::warn!(%inbox_url, "failed to deliver remote dm: {e:?}");
                }
            });
        }

        // Echo to sender only
        let event = WsEvent::NewDm(DmPayload {
            message_id: msg.id,
            sender_address: sender.federated_address(&local_domain),
            sender_display_name: sender_display_name.clone(),
            content: msg.content.clone(),
            created_at: msg.created_at,
            reply_to_id: body.reply_to_id,
            reply_to_content: reply_to_content.clone(),
            reply_to_sender: reply_to_sender.clone(),
        });
        state.hub.send_to_user(&sender_id, event);

        tracing::info!(
            sender = %sender.federated_address(&local_domain),
            recipient = %format!("{}@{}", username, domain),
            "direct message dispatched to remote actor via ActivityPub"
        );

        Ok((StatusCode::CREATED, Json(MessageResponse {
            id: msg.id,
            sender_actor_uri: msg.sender_actor_uri,
            sender_display_name: sender_display_name.clone(),
            recipient_actor_uri: msg.recipient_actor_uri,
            content: msg.content,
            activity_uri: msg.activity_uri,
            federation_status: msg.federation_status,
            created_at: msg.created_at,
            reply_to_id: body.reply_to_id,
            reply_to_content,
            reply_to_sender,
            reactions: vec![],
        })))
    } else {
        // ── Local delivery ────────────────────────────────────────────────────
        let recipient = users::find_by_username(&state.pool, username)
            .await
            .map_err(|e| OidcError::server_error(e.to_string()))?
            .ok_or_else(|| OidcError::not_found("Recipient not found"))?;

        if recipient.id == sender_id {
            return Err(OidcError::invalid_request("Cannot send a DM to yourself"));
        }

        let recipient_actor_uri = recipient.actor_uri.as_deref()
            .ok_or_else(|| OidcError::server_error("Recipient has no actor_uri"))?;

        let msg = messages::create_message(
            &state.pool,
            sender_actor_uri,
            recipient_actor_uri,
            &body.content,
            &activity_uri,
            body.reply_to_id,
        )
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

        let event = WsEvent::NewDm(DmPayload {
            message_id: msg.id,
            sender_address: sender.federated_address(&local_domain),
            sender_display_name: sender_display_name.clone(),
            content: msg.content.clone(),
            created_at: msg.created_at,
            reply_to_id: body.reply_to_id,
            reply_to_content: reply_to_content.clone(),
            reply_to_sender: reply_to_sender.clone(),
        });

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
            sender = %sender.federated_address(&local_domain),
            recipient = %recipient.federated_address(&local_domain),
            "direct message sent"
        );

        Ok((StatusCode::CREATED, Json(MessageResponse {
            id: msg.id,
            sender_actor_uri: msg.sender_actor_uri,
            sender_display_name,
            recipient_actor_uri: msg.recipient_actor_uri,
            content: msg.content,
            activity_uri: msg.activity_uri,
            federation_status: msg.federation_status,
            created_at: msg.created_at,
            reply_to_id: body.reply_to_id,
            reply_to_content,
            reply_to_sender,
            reactions: vec![],
        })))
    }
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
    let mut parts = addr.splitn(2, '@');
    let username = parts.next().unwrap_or(addr);
    let domain_opt = parts.next();

    let is_remote = domain_opt.map_or(false, |d| d != state.config.domain);

    // Resolve the other side's actor URI — local DB or remote_actors cache.
    let other_actor_uri_owned: String = if is_remote {
        let domain = domain_opt.unwrap();
        let issuer = state.config.issuer();
        let scheme = if issuer.starts_with("https") { "https" } else { "http" };
        let guessed = format!("{}://{}/users/{}", scheme, domain, username);
        // Check cache; if missing fall back to WebFinger
        match remote_actors::find_by_actor_uri(&state.pool, &guessed).await {
            Ok(Some(ra)) => ra.actor_uri,
            _ => {
                let ra = delivery::resolve_remote_actor(username, domain, &issuer).await?;
                let actor_url = ra.actor_url.clone();
                let inbox = ra.inbox.clone();
                let pool = state.pool.clone();
                let domain_owned = domain.to_string();
                let display = ra.display_name.clone();
                let avatar = ra.avatar_url.clone();
                tokio::spawn(async move {
                    if let Err(e) = remote_actors::upsert(
                        &pool,
                        &actor_url,
                        Some(&inbox),
                        &domain_owned,
                        display.as_deref(),
                        avatar.as_deref(),
                    )
                    .await
                    {
                        tracing::warn!("failed to cache remote actor: {e}");
                    }
                });
                ra.actor_url
            }
        }
    } else {
        let other = users::find_by_username(&state.pool, username)
            .await
            .map_err(|e| OidcError::server_error(e.to_string()))?
            .ok_or_else(|| OidcError::not_found("User not found"))?;
        other.actor_uri.ok_or_else(|| OidcError::server_error("User has no actor_uri"))?
    };
    let other_actor_uri = other_actor_uri_owned.as_str();

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

    // Batch-fetch reactions for all messages in this page.
    let message_ids: Vec<Uuid> = msgs.iter().map(|m| m.id).collect();
    let reaction_rows = reactions::get_reactions_for_messages(
        &state.pool,
        &message_ids,
        caller_actor_uri,
    )
    .await
    .map_err(|e| OidcError::server_error(e.to_string()))?;

    // Group reactions by message_id.
    let mut reactions_map: HashMap<Uuid, Vec<ReactionGroup>> = HashMap::new();
    for row in reaction_rows {
        reactions_map
            .entry(row.message_id)
            .or_default()
            .push(ReactionGroup {
                emoji: row.emoji,
                count: row.count,
                reacted_by_me: row.reacted_by_me,
            });
    }

    // Resolve display names for the two participants upfront (at most 2 DB lookups).
    let caller_display = display_name_for_actor(&state.pool, caller_actor_uri).await;
    let other_display = display_name_for_actor(&state.pool, other_actor_uri).await;

    let responses = msgs
        .into_iter()
        .map(|m| {
            let sender_display = if m.sender_actor_uri == caller_actor_uri {
                caller_display.clone()
            } else {
                other_display.clone()
            };
            let msg_reactions = reactions_map.remove(&m.id).unwrap_or_default();
            MessageResponse {
                id: m.id,
                sender_actor_uri: m.sender_actor_uri,
                sender_display_name: sender_display,
                recipient_actor_uri: m.recipient_actor_uri,
                content: m.content,
                activity_uri: m.activity_uri,
                federation_status: m.federation_status,
                created_at: m.created_at,
                reply_to_id: m.reply_to_id,
                reply_to_content: m.reply_to_content,
                reply_to_sender: m.reply_to_sender,
                reactions: msg_reactions,
            }
        })
        .collect();

    // Mark conversation as read when fetching the initial page.
    if query.cursor_created_at.is_none() {
        let other = other_actor_uri.to_string();
        let pool = state.pool.clone();
        tokio::spawn(async move {
            if let Err(e) = dm_reads::mark_read(&pool, caller_id, &other).await {
                tracing::warn!("failed to mark conversation as read: {e}");
            }
        });
    }

    Ok(Json(responses))
}

// ─── List conversations ───────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct ConversationListItem {
    pub other_actor_uri: String,
    pub other_display_name: Option<String>,
    pub unread_count: i64,
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

    let summaries = messages::list_conversations(&state.pool, caller_id, caller_actor_uri)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    let mut items = Vec::with_capacity(summaries.len());
    for s in summaries {
        let other_display = display_name_for_actor(&state.pool, &s.other_actor_uri).await;
        items.push(ConversationListItem {
            other_actor_uri: s.other_actor_uri,
            other_display_name: other_display,
            unread_count: s.unread_count,
            last_message_at: s.last_message_at,
        });
    }

    Ok(Json(items))
}

// ─── Add reaction ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct AddReactionRequest {
    pub emoji: String,
}

/// POST /api/dm/:message_id/reactions
#[tracing::instrument(skip_all, fields(message_id = %message_id))]
pub async fn add_reaction(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(message_id): Path<Uuid>,
    Json(body): Json<AddReactionRequest>,
) -> Result<StatusCode, OidcError> {
    let caller_id = require_auth(&state, &headers).await?;

    if body.emoji.is_empty() {
        return Err(OidcError::invalid_request("Emoji cannot be empty"));
    }

    let caller = users::find_by_id(&state.pool, caller_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::server_error("Caller not found"))?;

    let caller_actor_uri = caller.actor_uri.as_deref()
        .ok_or_else(|| OidcError::server_error("Caller has no actor_uri"))?;

    // Verify message exists and caller is a participant.
    let msg = messages::find_by_id(&state.pool, message_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::not_found("Message not found"))?;

    if msg.sender_actor_uri != caller_actor_uri && msg.recipient_actor_uri != caller_actor_uri {
        return Err(OidcError::not_found("Message not found"));
    }

    reactions::add_reaction(&state.pool, message_id, caller_actor_uri, &body.emoji)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    // Determine the other participant to notify.
    let other_actor_uri = if msg.sender_actor_uri == caller_actor_uri {
        &msg.recipient_actor_uri
    } else {
        &msg.sender_actor_uri
    };

    let event = WsEvent::MessageReactionAdded(ReactionPayload {
        message_id,
        reactor_actor_uri: caller_actor_uri.to_string(),
        emoji: body.emoji.clone(),
    });

    // Check if the other participant is local.
    let base = state.config.issuer();
    if other_actor_uri.starts_with(&format!("{}/users/", base)) {
        // Local: push via WS + broker.
        if let Ok(Some(other_user)) = users::find_by_actor_uri(&state.pool, other_actor_uri).await {
            state.hub.send_to_user(&other_user.id, event.clone());
            if let Ok(json) = serde_json::to_string(&event) {
                let broker = state.broker.clone();
                let rid = other_user.id;
                tokio::spawn(async move {
                    if let Err(e) = broker.publish(rid, &json).await {
                        tracing::warn!(%rid, "broker publish failed: {e}");
                    }
                });
            }
        }
    } else {
        // Remote: deliver Like activity via ActivityPub.
        let like_activity_uri = format!(
            "{}/users/{}/activities/{}",
            base,
            caller.username,
            Uuid::new_v4(),
        );
        let activity = activitypub::Activity::like(
            &like_activity_uri,
            caller_actor_uri,
            &msg.activity_uri,
            &body.emoji,
        );
        if let Ok(activity_value) = serde_json::to_value(&activity) {
            // Resolve remote inbox.
            if let Ok(Some(ra)) = remote_actors::find_by_actor_uri(&state.pool, other_actor_uri).await {
                if let Some(inbox_url) = ra.inbox_url {
                    let state_clone = state.clone();
                    let sender_username = caller.username.clone();
                    tokio::spawn(async move {
                        if let Err(e) = delivery::deliver_activity(
                            &state_clone, &inbox_url, &activity_value, &sender_username,
                        ).await {
                            tracing::warn!(%inbox_url, "failed to deliver Like activity: {e:?}");
                        }
                    });
                }
            }
        }
    }

    // Also push to the reactor themselves (for multi-device).
    state.hub.send_to_user(&caller_id, event);

    Ok(StatusCode::CREATED)
}

// ─── Remove reaction ──────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct RemoveReactionQuery {
    pub emoji: String,
}

/// DELETE /api/dm/:message_id/reactions?emoji=...
#[tracing::instrument(skip_all, fields(message_id = %message_id))]
pub async fn remove_reaction(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(message_id): Path<Uuid>,
    Query(query): Query<RemoveReactionQuery>,
) -> Result<StatusCode, OidcError> {
    let caller_id = require_auth(&state, &headers).await?;

    if query.emoji.is_empty() {
        return Err(OidcError::invalid_request("Emoji cannot be empty"));
    }

    let caller = users::find_by_id(&state.pool, caller_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::server_error("Caller not found"))?;

    let caller_actor_uri = caller.actor_uri.as_deref()
        .ok_or_else(|| OidcError::server_error("Caller has no actor_uri"))?;

    // Verify message exists and caller is a participant.
    let msg = messages::find_by_id(&state.pool, message_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::not_found("Message not found"))?;

    if msg.sender_actor_uri != caller_actor_uri && msg.recipient_actor_uri != caller_actor_uri {
        return Err(OidcError::not_found("Message not found"));
    }

    let deleted = reactions::remove_reaction(&state.pool, message_id, caller_actor_uri, &query.emoji)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    if !deleted {
        return Ok(StatusCode::NO_CONTENT);
    }

    let other_actor_uri = if msg.sender_actor_uri == caller_actor_uri {
        &msg.recipient_actor_uri
    } else {
        &msg.sender_actor_uri
    };

    let event = WsEvent::MessageReactionRemoved(ReactionPayload {
        message_id,
        reactor_actor_uri: caller_actor_uri.to_string(),
        emoji: query.emoji.clone(),
    });

    let base = state.config.issuer();
    if other_actor_uri.starts_with(&format!("{}/users/", base)) {
        if let Ok(Some(other_user)) = users::find_by_actor_uri(&state.pool, other_actor_uri).await {
            state.hub.send_to_user(&other_user.id, event.clone());
            if let Ok(json) = serde_json::to_string(&event) {
                let broker = state.broker.clone();
                let rid = other_user.id;
                tokio::spawn(async move {
                    if let Err(e) = broker.publish(rid, &json).await {
                        tracing::warn!(%rid, "broker publish failed: {e}");
                    }
                });
            }
        }
    } else {
        // Remote: deliver Undo{Like} via ActivityPub.
        let undo_activity_uri = format!(
            "{}/users/{}/activities/{}",
            base,
            caller.username,
            Uuid::new_v4(),
        );
        let like_value = serde_json::json!({
            "type": "Like",
            "actor": caller_actor_uri,
            "object": msg.activity_uri,
            "content": query.emoji,
        });
        let activity = activitypub::Activity::undo_like(
            &undo_activity_uri,
            caller_actor_uri,
            like_value,
        );
        if let Ok(activity_value) = serde_json::to_value(&activity) {
            if let Ok(Some(ra)) = remote_actors::find_by_actor_uri(&state.pool, other_actor_uri).await {
                if let Some(inbox_url) = ra.inbox_url {
                    let state_clone = state.clone();
                    let sender_username = caller.username.clone();
                    tokio::spawn(async move {
                        if let Err(e) = delivery::deliver_activity(
                            &state_clone, &inbox_url, &activity_value, &sender_username,
                        ).await {
                            tracing::warn!(%inbox_url, "failed to deliver Undo Like: {e:?}");
                        }
                    });
                }
            }
        }
    }

    state.hub.send_to_user(&caller_id, event);

    Ok(StatusCode::NO_CONTENT)
}
