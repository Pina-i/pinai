//! REST API handlers for Direct Messages and replies.
//!
//! After Phase 3 every DM body on the wire is an opaque MLS ciphertext.
//! Replies still carry a server-visible `reply_to_id` (used for thread
//! routing and soft-delete cascade), but the preview text + sender
//! display name move into the encrypted body and are reconstructed by
//! the client from its decrypted MLS stream. Reactions are gone from
//! this surface entirely — they're MLS application messages of
//! `kind = "reaction"`, indistinguishable from text on the wire.
//!
//! All endpoints require a valid Bearer access token.

use std::collections::HashMap;
use std::collections::HashSet;

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use idp_db::repos::{
    attachments as attachments_repo, conversation_reads, conversations, messages, remote_actors,
    users,
};
use idp_federation::actors::display_name_for_actor;
use idp_federation::auth::require_auth;
use idp_federation::delivery;
use idp_federation::mls as federation_mls;
use idp_realtime::{DmPayload, EditedDmPayload, WsEvent};
use idp_state::{AppState, OidcError};

// ─── Send a DM ────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct SendMessageRequest {
    /// Recipient's address, e.g. "@alice@idp.example.com" or "alice".
    pub recipient_address: String,
    /// Pre-encrypted MLSMessage body, base64-encoded. Server never inspects.
    pub mls_ciphertext: String,
    /// Optional: reply to an existing message. The plaintext preview lives
    /// inside the encrypted body; only the parent ID is server-visible.
    pub reply_to_id: Option<Uuid>,
    /// Optional: orphan attachment IDs returned by `POST /api/attachments`.
    /// Caller must own each one (matching `uploaded_by_actor_uri`) and they
    /// must still be unlinked.
    #[serde(default)]
    pub attachment_ids: Vec<Uuid>,
    /// Phase 5b: client-supplied UUID for the conversation. Required
    /// when the client just bootstrapped a new MLS group and needs the
    /// server's `conversations.id` to match the MLS `group_id` it
    /// already used. Omitted on subsequent sends — the server reuses
    /// the existing conversation it finds via `find_dm_between`.
    pub conversation_id: Option<Uuid>,
}

#[derive(Debug, Serialize)]
pub struct MessageResponse {
    pub id: Uuid,
    pub conversation_id: Uuid,
    pub sender_actor_uri: String,
    pub sender_display_name: Option<String>,
    /// TLS-encoded MLSMessage, base64-encoded. Echoed back to the sender so
    /// optimistic UI can swap directly without holding the original blob.
    pub mls_ciphertext: String,
    pub activity_uri: String,
    pub federation_status: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "time::serde::rfc3339::option")]
    pub edited_at: Option<OffsetDateTime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_to_id: Option<Uuid>,
    pub attachments: Vec<crate::attachments::AttachmentMetadata>,
}

/// Maximum size of an inbound MLS ciphertext blob — ~64 KiB after base64 is
/// generous for application messages (typical text DMs are ~200 bytes;
/// edits + reaction operations even smaller). Caps server-side abuse.
const MAX_MLS_CIPHERTEXT_BYTES: usize = 64 * 1024;

fn decode_mls_ciphertext(b64: &str) -> Result<Vec<u8>, OidcError> {
    let bytes = B64
        .decode(b64)
        .map_err(|_| OidcError::invalid_request("`mls_ciphertext` is not valid base64"))?;
    if bytes.is_empty() {
        return Err(OidcError::invalid_request("`mls_ciphertext` is empty"));
    }
    if bytes.len() > MAX_MLS_CIPHERTEXT_BYTES {
        return Err(OidcError::invalid_request(format!(
            "`mls_ciphertext` exceeds {} bytes",
            MAX_MLS_CIPHERTEXT_BYTES
        )));
    }
    Ok(bytes)
}

/// POST /api/dm
#[tracing::instrument(skip_all)]
pub async fn send_message(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<SendMessageRequest>,
) -> Result<(StatusCode, Json<MessageResponse>), OidcError> {
    let sender_id = require_auth(&state, &headers).await?;

    if body.attachment_ids.len() > state.config.attachment_max_files_per_message {
        return Err(OidcError::invalid_request(format!(
            "too many attachments (max {} per message)",
            state.config.attachment_max_files_per_message
        )));
    }

    let mls_ciphertext = decode_mls_ciphertext(&body.mls_ciphertext)?;

    let sender = users::find_by_id(&state.pool, sender_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::server_error("Sender not found"))?;

    let sender_actor_uri = sender.actor_uri.as_deref()
        .ok_or_else(|| OidcError::server_error("Sender has no actor_uri"))?;

    let sender_display_name: Option<String> =
        Some(sender.display_name.clone().unwrap_or_else(|| sender.username.clone()));

    // Pre-validate attachments BEFORE creating the message so a 400 here
    // doesn't leave a content-less message in the DB.
    if !body.attachment_ids.is_empty() {
        let owned = attachments_repo::find_orphans_owned_by(
            &state.pool,
            &body.attachment_ids,
            sender_actor_uri,
        )
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;
        if owned.len() != body.attachment_ids.len() {
            return Err(OidcError::invalid_request(
                "one or more attachment IDs are missing, already linked, or not owned by sender",
            ));
        }
    }

    // Replies: the parent ID is server-visible for routing, but the preview
    // text/sender lives in the encrypted body. Only validation here is that
    // the parent message actually exists.
    let mut parent_activity_uri: Option<String> = None;
    if let Some(parent_id) = body.reply_to_id {
        let parent = messages::find_by_id(&state.pool, parent_id)
            .await
            .map_err(|e| OidcError::server_error(e.to_string()))?
            .ok_or_else(|| OidcError::not_found("Parent message not found"))?;
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
        let scheme = state.config.scheme();
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

        // Get or create the DM conversation. When the client passes a
        // pinned `conversation_id` (Phase 5b: the MLS `group_id` it
        // just bootstrapped), use it; otherwise let the server pick
        // one.
        let (conversation_id, _created) = match body.conversation_id {
            Some(client_id) => conversations::get_or_create_dm_with_id(
                &state.pool,
                client_id,
                sender_actor_uri,
                &recipient_actor_uri,
            )
            .await,
            None => conversations::get_or_create_dm(
                &state.pool,
                sender_actor_uri,
                &recipient_actor_uri,
            )
            .await,
        }
        .map_err(|e| OidcError::server_error(e.to_string()))?;

        let msg = messages::create_message(
            &state.pool,
            conversation_id,
            sender_actor_uri,
            &mls_ciphertext,
            &activity_uri,
            body.reply_to_id,
        )
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

        let attachments_metadata =
            link_message_attachments(&state, &body.attachment_ids, msg.id, sender_actor_uri).await?;

        // Build the MLS-flavored Create{Note} envelope and deliver in the
        // background. A missed delivery self-heals via the recipient's
        // catch-up pull on reconnect, so no durable outbox is needed.
        let mut activity = federation_mls::build_application_create_activity(
            &activity_uri,
            &activity_uri,
            sender_actor_uri,
            &recipient_actor_uri,
            conversation_id,
            &mls_ciphertext,
            parent_activity_uri.as_deref(),
        );
        crate::attachments::inject_attachments_into_ap_activity(
            &mut activity,
            &state.config.issuer(),
            &attachments_metadata,
        );
        let state_clone = state.clone();
        let sender_username = sender.username.clone();
        let inbox_for_task = inbox_url.clone();
        tokio::spawn(async move {
            if let Err(e) =
                delivery::deliver_activity(&state_clone, &inbox_for_task, &activity, &sender_username)
                    .await
            {
                tracing::warn!(%inbox_for_task, "failed to deliver remote dm: {e:?}");
            }
        });

        // Echo to sender only — recipient's IdP will push them their own copy
        // when the inbox handler persists it on the other side.
        let event = WsEvent::NewDm(DmPayload {
            message_id: msg.id,
            conversation_id,
            kind: "dm".to_string(),
            sender_address: sender.federated_address(&local_domain),
            sender_display_name: sender_display_name.clone(),
            mls_ciphertext: B64.encode(&msg.mls_ciphertext),
            created_at: msg.created_at,
            reply_to_id: body.reply_to_id,
            attachments: attachments_metadata.iter().map(Into::into).collect(),
            client_id: None,
        });
        state.hub.send_to_user(&sender_id, event);

        tracing::info!(
            sender = %sender.federated_address(&local_domain),
            recipient = %format!("{}@{}", username, domain),
            "direct message dispatched to remote actor via ActivityPub"
        );

        Ok((StatusCode::CREATED, Json(MessageResponse {
            id: msg.id,
            conversation_id,
            sender_actor_uri: msg.sender_actor_uri,
            sender_display_name,
            mls_ciphertext: B64.encode(&msg.mls_ciphertext),
            activity_uri: msg.activity_uri,
            federation_status: msg.federation_status,
            created_at: msg.created_at,
            edited_at: msg.edited_at,
            reply_to_id: body.reply_to_id,
            attachments: attachments_metadata,
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

        // Get or create the DM conversation. When the client passes a
        // pinned `conversation_id` (Phase 5b: the MLS `group_id` it
        // just bootstrapped), use it; otherwise let the server pick.
        let (conversation_id, _created) = match body.conversation_id {
            Some(client_id) => conversations::get_or_create_dm_with_id(
                &state.pool,
                client_id,
                sender_actor_uri,
                recipient_actor_uri,
            )
            .await,
            None => conversations::get_or_create_dm(
                &state.pool,
                sender_actor_uri,
                recipient_actor_uri,
            )
            .await,
        }
        .map_err(|e| OidcError::server_error(e.to_string()))?;

        let msg = messages::create_message(
            &state.pool,
            conversation_id,
            sender_actor_uri,
            &mls_ciphertext,
            &activity_uri,
            body.reply_to_id,
        )
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

        let attachments_metadata =
            link_message_attachments(&state, &body.attachment_ids, msg.id, sender_actor_uri).await?;

        let event = WsEvent::NewDm(DmPayload {
            message_id: msg.id,
            conversation_id,
            kind: "dm".to_string(),
            sender_address: sender.federated_address(&local_domain),
            sender_display_name: sender_display_name.clone(),
            mls_ciphertext: B64.encode(&msg.mls_ciphertext),
            created_at: msg.created_at,
            reply_to_id: body.reply_to_id,
            attachments: attachments_metadata.iter().map(Into::into).collect(),
            client_id: None,
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
            conversation_id,
            sender_actor_uri: msg.sender_actor_uri,
            sender_display_name,
            mls_ciphertext: B64.encode(&msg.mls_ciphertext),
            activity_uri: msg.activity_uri,
            federation_status: msg.federation_status,
            created_at: msg.created_at,
            edited_at: msg.edited_at,
            reply_to_id: body.reply_to_id,
            attachments: attachments_metadata,
        })))
    }
}

/// Link the given orphan attachments to a message and return metadata for the
/// response. Pre-validation of ownership/orphan status has already happened at
/// the top of `send_message`; this is the side effect plus a fresh read for
/// the response shape.
async fn link_message_attachments(
    state: &AppState,
    attachment_ids: &[Uuid],
    message_id: Uuid,
    sender_actor_uri: &str,
) -> Result<Vec<crate::attachments::AttachmentMetadata>, OidcError> {
    if attachment_ids.is_empty() {
        return Ok(Vec::new());
    }
    let linked = attachments_repo::link_to_message(
        &state.pool,
        attachment_ids,
        message_id,
        sender_actor_uri,
    )
    .await
    .map_err(|e| OidcError::server_error(e.to_string()))?;

    if linked as usize != attachment_ids.len() {
        tracing::warn!(
            requested = attachment_ids.len(),
            linked,
            %message_id,
            "fewer attachments linked than requested (likely race with concurrent send)"
        );
    }

    let rows = attachments_repo::find_for_message(&state.pool, message_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    Ok(rows
        .iter()
        .map(crate::attachments::AttachmentMetadata::from)
        .collect())
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

/// GET /api/dm/:conversation_id?cursor_created_at=...&cursor_id=...&limit=50
/// Conversation history, newest-first with keyset pagination.
#[tracing::instrument(skip_all, fields(conversation_id = %conversation_id))]
pub async fn get_conversation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(conversation_id): Path<Uuid>,
    Query(query): Query<ConversationQuery>,
) -> Result<Json<Vec<MessageResponse>>, OidcError> {
    let caller_id = require_auth(&state, &headers).await?;

    let caller = users::find_by_id(&state.pool, caller_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::server_error("Caller not found"))?;

    let caller_actor_uri = caller.actor_uri.as_deref()
        .ok_or_else(|| OidcError::server_error("Caller has no actor_uri"))?;

    // Verify the caller is a member of this conversation.
    let members = conversations::get_members(&state.pool, conversation_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    if !members.iter().any(|m| m.actor_uri == caller_actor_uri) {
        return Err(OidcError::not_found("Conversation not found"));
    }

    let limit = query.limit.unwrap_or(50).min(100);

    let msgs = match (query.cursor_created_at, query.cursor_id) {
        (Some(cursor_ts), Some(cursor_id)) => {
            messages::get_conversation_before(
                &state.pool,
                conversation_id,
                cursor_ts,
                cursor_id,
                limit,
            )
            .await
        }
        _ => {
            messages::get_conversation(&state.pool, conversation_id, limit).await
        }
    }
    .map_err(|e| OidcError::server_error(e.to_string()))?;

    // Batch-fetch attachments for all messages in this page.
    let message_ids: Vec<Uuid> = msgs.iter().map(|m| m.id).collect();
    let attachment_rows = attachments_repo::find_for_messages(&state.pool, &message_ids)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;
    let mut attachments_map: HashMap<Uuid, Vec<crate::attachments::AttachmentMetadata>> =
        HashMap::new();
    for row in &attachment_rows {
        if let Some(mid) = row.message_id {
            attachments_map
                .entry(mid)
                .or_default()
                .push(crate::attachments::AttachmentMetadata::from(row));
        }
    }

    // Resolve display names for the senders only — replies' parent senders
    // live in the encrypted body, so the server no longer joins them.
    let unique_senders: Vec<&str> = {
        let mut set = HashSet::new();
        for m in &msgs {
            set.insert(m.sender_actor_uri.as_str());
        }
        set.into_iter().collect()
    };
    let mut display_names: HashMap<String, Option<String>> = HashMap::new();
    for actor_uri in unique_senders {
        let dn = display_name_for_actor(&state.pool, actor_uri).await;
        display_names.insert(actor_uri.to_string(), dn);
    }

    let responses = msgs
        .into_iter()
        .map(|m| {
            let sender_display = display_names.get(&m.sender_actor_uri).cloned().flatten();
            let msg_attachments = attachments_map.remove(&m.id).unwrap_or_default();
            MessageResponse {
                id: m.id,
                conversation_id: m.conversation_id,
                sender_actor_uri: m.sender_actor_uri,
                sender_display_name: sender_display,
                mls_ciphertext: B64.encode(&m.mls_ciphertext),
                activity_uri: m.activity_uri,
                federation_status: m.federation_status,
                created_at: m.created_at,
                edited_at: m.edited_at,
                reply_to_id: m.reply_to_id,
                attachments: msg_attachments,
            }
        })
        .collect();

    // Mark conversation as read when fetching the initial page.
    if query.cursor_created_at.is_none() {
        let pool = state.pool.clone();
        tokio::spawn(async move {
            if let Err(e) = conversation_reads::mark_read(&pool, caller_id, conversation_id).await {
                tracing::warn!("failed to mark conversation as read: {e}");
            }
        });
    }

    Ok(Json(responses))
}

// ─── List conversations ───────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct ConversationMemberInfo {
    #[serde(rename = "actorUri")]
    pub actor_uri: String,
    #[serde(rename = "displayName")]
    pub display_name: Option<String>,
    #[serde(rename = "avatarUrl")]
    pub avatar_url: Option<String>,
}

/// Slim conversation row. Phase 3 dropped `last_message_preview` (the body
/// is opaque ciphertext); the client computes its own preview from its
/// decrypted MLS stream.
#[derive(Debug, Serialize)]
pub struct ConversationListItem {
    pub conversation_id: Uuid,
    pub kind: String,
    pub name: Option<String>,
    pub members: Vec<ConversationMemberInfo>,
    pub last_message_sender: Option<String>,
    pub unread_count: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_message_at: Option<OffsetDateTime>,
}

/// GET /api/dm — list all conversations, most-recent first
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

    let items: Vec<ConversationListItem> = summaries
        .into_iter()
        .map(|s| {
            // Parse the members JSON array from the DB.
            let members: Vec<ConversationMemberInfo> = serde_json::from_value(s.members.clone())
                .unwrap_or_default();
            ConversationListItem {
                conversation_id: s.conversation_id,
                kind: s.kind,
                name: s.name,
                members,
                last_message_sender: s.last_message_sender,
                unread_count: s.unread_count,
                last_message_at: s.last_message_at,
            }
        })
        .collect();

    Ok(Json(items))
}

// ─── Edit a message ───────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct EditMessageRequest {
    /// Replacement MLSMessage body, base64-encoded. Server replaces the row's
    /// ciphertext and stamps `edited_at` — opaque to what changed.
    pub mls_ciphertext: String,
}

/// PATCH /api/dm/:message_id/edit
/// Replace the ciphertext of a message. Only the original sender can edit.
#[tracing::instrument(skip_all, fields(message_id = %message_id))]
pub async fn edit_message(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(message_id): Path<Uuid>,
    Json(body): Json<EditMessageRequest>,
) -> Result<Json<MessageResponse>, OidcError> {
    let caller_id = require_auth(&state, &headers).await?;

    let new_mls_ciphertext = decode_mls_ciphertext(&body.mls_ciphertext)?;

    let caller = users::find_by_id(&state.pool, caller_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::server_error("Caller not found"))?;

    let caller_actor_uri = caller.actor_uri.as_deref()
        .ok_or_else(|| OidcError::server_error("Caller has no actor_uri"))?;

    // Update — the WHERE clause enforces sender ownership and non-deleted.
    let updated = messages::edit_message(&state.pool, message_id, caller_actor_uri, &new_mls_ciphertext)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::not_found("Message not found or you are not the sender"))?;

    let edited_at = updated.edited_at
        .ok_or_else(|| OidcError::server_error("edited_at missing after update"))?;

    let event = WsEvent::MessageEdited(EditedDmPayload {
        message_id: updated.id,
        new_mls_ciphertext: B64.encode(&updated.mls_ciphertext),
        edited_at,
    });

    // Notify all other members of the conversation.
    let members = conversations::get_members(&state.pool, updated.conversation_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    let base = state.config.issuer();
    for member in &members {
        if member.actor_uri == caller_actor_uri {
            continue;
        }
        if member.actor_uri.starts_with(&format!("{}/users/", base)) {
            // Local recipient: push via WS + broker.
            if let Ok(Some(other_user)) = users::find_by_actor_uri(&state.pool, &member.actor_uri).await {
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
            // Remote recipient: deliver Update{Note} carrying the new MLS
            // ciphertext. Same `mediaType: application/mls` envelope as
            // Create{Note} so the receiving side's mediaType gate accepts it.
            let update_activity_uri = format!(
                "{}/users/{}/activities/{}",
                base,
                caller.username,
                Uuid::new_v4(),
            );
            let activity = federation_mls::build_application_update_activity(
                &update_activity_uri,
                &updated.activity_uri,
                caller_actor_uri,
                &member.actor_uri,
                updated.conversation_id,
                &new_mls_ciphertext,
            );
            if let Ok(Some(ra)) = remote_actors::find_by_actor_uri(&state.pool, &member.actor_uri).await {
                if let Some(inbox_url) = ra.inbox_url {
                    let state_clone = state.clone();
                    let sender_username = caller.username.clone();
                    tokio::spawn(async move {
                        if let Err(e) = delivery::deliver_activity(
                            &state_clone, &inbox_url, &activity, &sender_username,
                        ).await {
                            tracing::warn!(%inbox_url, "failed to deliver Update{{Note}}: {e:?}");
                        }
                    });
                }
            }
        }
    }

    // Echo to sender (multi-device).
    state.hub.send_to_user(&caller_id, event);

    let sender_display_name = Some(caller.display_name.unwrap_or(caller.username));

    tracing::info!(message_id = %updated.id, "message edited");

    // Edits don't change attachments — pull the existing ones for the response.
    let attachments_metadata: Vec<crate::attachments::AttachmentMetadata> =
        attachments_repo::find_for_message(&state.pool, updated.id)
            .await
            .map_err(|e| OidcError::server_error(e.to_string()))?
            .iter()
            .map(crate::attachments::AttachmentMetadata::from)
            .collect();

    Ok(Json(MessageResponse {
        id: updated.id,
        conversation_id: updated.conversation_id,
        sender_actor_uri: updated.sender_actor_uri,
        sender_display_name,
        mls_ciphertext: B64.encode(&updated.mls_ciphertext),
        activity_uri: updated.activity_uri,
        federation_status: updated.federation_status,
        created_at: updated.created_at,
        edited_at: Some(edited_at),
        reply_to_id: updated.reply_to_id,
        attachments: attachments_metadata,
    }))
}
