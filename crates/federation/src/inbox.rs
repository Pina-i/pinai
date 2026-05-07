//! POST /users/:username/inbox
//!
//! Receives ActivityPub activities from remote and local servers.
//! Supported activities:
//!   - Follow         → creates a pending friendship
//!   - Accept{Follow} → marks a friendship as accepted
//!   - Reject{Follow} → deletes the friendship row
//!   - Undo{Follow}   → deletes the friendship
//!   - Undo{Like}     → removes a message reaction
//!   - Create{Note}   → stores a direct message (supports inReplyTo)
//!   - Update{Person} → updates remote_actors cache + propagates profile changes
//!   - Like           → adds a message reaction

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde_json::Value;
use uuid::Uuid;

use idp_db::repos::{
    attachments, conversations, friendships, messages, reactions, remote_actors, users,
};

use idp_realtime::{DmPayload, EditedDmPayload, FriendshipPayload, ProfileUpdatePayload, ReactionPayload, WsAttachment, WsEvent};

use idp_state::{AppState, OidcError};

use crate::actors::display_name_for_actor;

/// POST /users/:slug/inbox
#[tracing::instrument(skip_all, fields(slug = %slug))]
pub async fn post_inbox(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    _headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<StatusCode, OidcError> {
    // 1. Resolve the inbox owner.
    let actor_uri = format!("{}/users/{}", state.config.issuer(), slug);
    let recipient = users::find_by_actor_uri(&state.pool, &actor_uri)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::not_found("User not found"))?;

    let activity_type = body
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    tracing::debug!(
        recipient = %recipient.username,
        activity_type = %activity_type,
        "inbox activity received"
    );

    match activity_type.as_str() {
        "Follow" => handle_follow(&state, &body, &recipient).await?,
        "Accept" => handle_accept(&state, &body).await?,
        "Reject" => handle_reject(&state, &body).await?,
        "Undo" => handle_undo(&state, &body, &recipient).await?,
        "Create" => handle_create(&state, &body, &recipient).await?,
        "Update" => handle_update(&state, &body, &recipient).await?,
        "Like" => handle_like(&state, &body, &recipient).await?,
        other => {
            tracing::warn!(activity_type = %other, "unhandled activity type in inbox");
        }
    }

    Ok(StatusCode::ACCEPTED)
}

// ─── Follow (friend request) ─────────────────────────────────────────────────

async fn handle_follow(
    state: &AppState,
    body: &Value,
    recipient: &idp_db::models::User,
) -> Result<(), OidcError> {
    let actor_url = body
        .get("actor")
        .and_then(|v| v.as_str())
        .ok_or_else(|| OidcError::invalid_request("Follow missing actor field"))?;

    let recipient_actor_uri = recipient.actor_uri.as_deref()
        .ok_or_else(|| OidcError::server_error("Recipient has no actor_uri"))?;

    // Check if this is a local actor.
    let base = state.config.issuer();
    if let Some(follower) = local_actor(actor_url, &base, &state.pool).await {
        // Local-to-local: create mutual friendships and auto-accept.
        let follower_uri = follower.actor_uri.as_deref()
            .ok_or_else(|| OidcError::server_error("Follower has no actor_uri"))?;

        // Follower → recipient
        let f1 = friendships::create_friendship(
            &state.pool,
            follower.id,
            recipient_actor_uri,
            recipient.avatar_url.as_deref(),
        )
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;
        friendships::set_status(&state.pool, f1.id, "accepted")
            .await
            .map_err(|e| OidcError::server_error(e.to_string()))?;

        // Recipient → follower
        let f2 = friendships::create_friendship(
            &state.pool,
            recipient.id,
            follower_uri,
            follower.avatar_url.as_deref(),
        )
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;
        friendships::set_status(&state.pool, f2.id, "accepted")
            .await
            .map_err(|e| OidcError::server_error(e.to_string()))?;

        // Push real-time notification to inbox owner.
        let payload = FriendshipPayload {
            friendship_id: f2.id,
            actor_uri: follower_uri.to_string(),
            username: follower.username.clone(),
            display_name: follower.display_name.clone(),
        };
        state.hub.send_to_user(&recipient.id, WsEvent::FriendRequest(payload.clone()));
        state.hub.send_to_user(&recipient.id, WsEvent::FriendAccepted(payload));

        tracing::info!(
            follower = %follower.username,
            recipient = %recipient.username,
            "local friend request auto-accepted"
        );
    } else {
        // Remote actor — cache and create a pending friendship for the recipient.
        let (remote_username, remote_domain) = parse_remote_actor_url(actor_url)
            .ok_or_else(|| OidcError::invalid_request("Cannot parse remote actor URL"))?;

        let display_name = fetch_remote_display_name(actor_url).await;

        // Upsert into remote_actors cache.
        remote_actors::upsert(
            &state.pool,
            actor_url,
            None,
            &remote_domain,
            display_name.as_deref(),
            None,
        )
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

        // Create pending friendship: recipient → remote actor.
        let friendship = friendships::create_friendship(
            &state.pool,
            recipient.id,
            actor_url,
            None,
        )
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

        // Notify inbox owner of pending friend request.
        state.hub.send_to_user(
            &recipient.id,
            WsEvent::FriendRequest(FriendshipPayload {
                friendship_id: friendship.id,
                actor_uri: actor_url.to_string(),
                username: remote_username.clone(),
                display_name,
            }),
        );

        tracing::info!(actor = %actor_url, recipient = %recipient.username, "remote friend request notified");
    }

    Ok(())
}

// ─── Accept ──────────────────────────────────────────────────────────────────

async fn handle_accept(state: &AppState, body: &Value) -> Result<(), OidcError> {
    let accepter_uri = body
        .get("actor")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Find the local user who sent the follow by looking at the object's actor.
    let follow_actor = body
        .get("object")
        .and_then(|o| {
            if o.is_string() {
                None
            } else {
                o.get("actor").and_then(|a| a.as_str())
            }
        });

    if let Some(local_actor_uri) = follow_actor {
        if let Ok(Some(local_user)) = users::find_by_actor_uri(&state.pool, local_actor_uri).await {
            if let Ok(Some(friendship)) = friendships::find_by_owner_and_uri(
                &state.pool,
                local_user.id,
                accepter_uri,
            ).await {
                friendships::set_status(&state.pool, friendship.id, "accepted")
                    .await
                    .map_err(|e| OidcError::server_error(e.to_string()))?;

                let (username, display_name) = resolve_remote_name(state, accepter_uri).await;
                state.hub.send_to_user(&local_user.id, WsEvent::FriendAccepted(FriendshipPayload {
                    friendship_id: friendship.id,
                    actor_uri: accepter_uri.to_string(),
                    username,
                    display_name,
                }));

                tracing::info!(user = %local_user.username, accepter = %accepter_uri, "friend request accepted via AP");
                return Ok(());
            }
        }
    }

    // Fallback: find any pending friendship with this accepter_uri.
    let base = state.config.issuer();
    let prefix = format!("{}/users/", base);

    let rows = sqlx::query_as::<_, idp_db::models::Friendship>(
        "SELECT * FROM friendships WHERE friend_actor_uri = $1 AND status = 'pending'",
    )
    .bind(accepter_uri)
    .fetch_all(&state.pool)
    .await
    .map_err(|e| OidcError::server_error(e.to_string()))?;

    for friendship in rows {
        if let Ok(Some(owner)) = users::find_by_id(&state.pool, friendship.owner_user_id).await {
            if owner.actor_uri.as_deref().map_or(false, |u| u.starts_with(&prefix)) {
                friendships::set_status(&state.pool, friendship.id, "accepted")
                    .await
                    .map_err(|e| OidcError::server_error(e.to_string()))?;

                let (username, display_name) = resolve_remote_name(state, accepter_uri).await;
                state.hub.send_to_user(&owner.id, WsEvent::FriendAccepted(FriendshipPayload {
                    friendship_id: friendship.id,
                    actor_uri: accepter_uri.to_string(),
                    username,
                    display_name,
                }));

                tracing::info!(friendship_id = %friendship.id, "friend accepted via AP (fallback)");
            }
        }
    }

    Ok(())
}

// ─── Reject ──────────────────────────────────────────────────────────────────

async fn handle_reject(state: &AppState, body: &Value) -> Result<(), OidcError> {
    let rejecter_uri = body
        .get("actor")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let rows = sqlx::query_as::<_, idp_db::models::Friendship>(
        "SELECT * FROM friendships WHERE friend_actor_uri = $1 AND status = 'pending'",
    )
    .bind(rejecter_uri)
    .fetch_all(&state.pool)
    .await
    .map_err(|e| OidcError::server_error(e.to_string()))?;

    for friendship in rows {
        friendships::delete_friendship(&state.pool, friendship.owner_user_id, rejecter_uri)
            .await
            .map_err(|e| OidcError::server_error(e.to_string()))?;

        state.hub.send_to_user(&friendship.owner_user_id, WsEvent::FriendRemoved(FriendshipPayload {
            friendship_id: friendship.id,
            actor_uri: rejecter_uri.to_string(),
            username: String::new(),
            display_name: None,
        }));

        tracing::info!(friendship_id = %friendship.id, "friend request rejected via AP");
    }

    Ok(())
}

// ─── Undo{Follow} ────────────────────────────────────────────────────────────

async fn handle_undo(
    state: &AppState,
    body: &Value,
    recipient: &idp_db::models::User,
) -> Result<(), OidcError> {
    let obj = body.get("object");
    let obj_type = obj
        .and_then(|o| o.get("type"))
        .and_then(|t| t.as_str())
        .unwrap_or("");

    match obj_type {
        "Follow" => handle_undo_follow(state, body, recipient).await,
        "Like" => handle_undo_like(state, body, recipient).await,
        _ => Ok(()),
    }
}

async fn handle_undo_follow(
    state: &AppState,
    body: &Value,
    recipient: &idp_db::models::User,
) -> Result<(), OidcError> {
    let actor_url = body
        .get("actor")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let recipient_actor_uri = recipient.actor_uri.as_deref().unwrap_or("");

    // Remove the friendship: recipient → actor.
    friendships::delete_friendship(&state.pool, recipient.id, actor_url)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    // If it was a local actor, also remove the reverse friendship.
    let base = state.config.issuer();
    if let Some(follower) = local_actor(actor_url, &base, &state.pool).await {
        friendships::delete_friendship(&state.pool, follower.id, recipient_actor_uri)
            .await
            .map_err(|e| OidcError::server_error(e.to_string()))?;
    }

    // Notify recipient.
    let (username, display_name) = resolve_remote_name(state, actor_url).await;
    state.hub.send_to_user(&recipient.id, WsEvent::FriendRemoved(FriendshipPayload {
        friendship_id: Uuid::nil(),
        actor_uri: actor_url.to_string(),
        username,
        display_name,
    }));

    tracing::info!(actor = %actor_url, recipient = %recipient.username, "unfriended via AP Undo");
    Ok(())
}

/// Handle Undo{Like} — remove a reaction from a remote actor.
async fn handle_undo_like(
    state: &AppState,
    body: &Value,
    recipient: &idp_db::models::User,
) -> Result<(), OidcError> {
    let actor_url = body
        .get("actor")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let inner = match body.get("object") {
        Some(o) if !o.is_string() => o,
        _ => return Ok(()),
    };

    let target_uri = inner
        .get("object")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let emoji = inner
        .get("content")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if target_uri.is_empty() || emoji.is_empty() {
        return Ok(());
    }

    let msg = match messages::find_by_activity_uri(&state.pool, target_uri).await {
        Ok(Some(m)) => m,
        _ => return Ok(()),
    };

    let deleted = reactions::remove_reaction(&state.pool, msg.id, actor_url, emoji)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    if deleted {
        let event = WsEvent::MessageReactionRemoved(ReactionPayload {
            message_id: msg.id,
            reactor_actor_uri: actor_url.to_string(),
            emoji: emoji.to_string(),
        });
        state.hub.send_to_user(&recipient.id, event);
    }

    tracing::info!(actor = %actor_url, message = %msg.id, emoji = %emoji, "reaction removed via AP Undo(Like)");
    Ok(())
}

// ─── Create{Note} (Direct Message) ──────────────────────────────────────────

async fn handle_create(
    state: &AppState,
    body: &Value,
    recipient: &idp_db::models::User,
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

    let actor_url = body.get("actor").and_then(|v| v.as_str()).unwrap_or("");

    let recipient_actor_uri = recipient.actor_uri.as_deref()
        .ok_or_else(|| OidcError::server_error("Recipient has no actor_uri"))?;

    // activity_uri is the AP activity ID; fall back to the note ID if the activity wrapper has no id
    let activity_uri = body
        .get("id")
        .and_then(|v| v.as_str())
        .or_else(|| obj.get("id").and_then(|v| v.as_str()))
        .ok_or_else(|| OidcError::invalid_request("Create activity missing id"))?;

    // Resolve inReplyTo: look up the parent message by its activity_uri to get
    // the local DB id for the reply_to_id FK.
    let in_reply_to_uri = obj.get("inReplyTo").and_then(|v| v.as_str());
    let mut reply_to_id: Option<Uuid> = None;
    let mut reply_to_content: Option<String> = None;
    let mut reply_to_sender: Option<String> = None;
    if let Some(parent_uri) = in_reply_to_uri {
        if let Ok(Some(parent)) = messages::find_by_activity_uri(&state.pool, parent_uri).await {
            reply_to_id = Some(parent.id);
            reply_to_content = Some(parent.content);
            // Resolve to display name instead of raw actor_uri.
            reply_to_sender = display_name_for_actor(&state.pool, &parent.sender_actor_uri).await
                .or_else(|| Some(parent.sender_actor_uri));
        }
    }

    // Get or create the DM conversation between sender and recipient.
    // If the AP activity includes a context field with a UUID, use that as the conversation ID.
    let context_uuid = body
        .get("object")
        .and_then(|o| o.get("context"))
        .and_then(|c| c.as_str())
        .and_then(|s| s.parse::<Uuid>().ok());

    let (conversation_id, _created) = if let Some(ctx_id) = context_uuid {
        conversations::get_or_create_dm_with_id(
            &state.pool,
            ctx_id,
            actor_url,
            recipient_actor_uri,
        )
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
    } else {
        conversations::get_or_create_dm(
            &state.pool,
            actor_url,
            recipient_actor_uri,
        )
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
    };

    let msg = messages::create_message(
        &state.pool,
        conversation_id,
        actor_url,
        &content,
        activity_uri,
        reply_to_id,
    )
    .await
    .map_err(|e| OidcError::server_error(e.to_string()))?;

    // Parse and persist any `Note.attachment` entries. Invalid entries are
    // skipped with a warning — we never reject the whole DM over a malformed
    // attachment.
    persist_inbound_attachments(state, msg.id, actor_url, obj.get("attachment")).await;

    // Look up the remote sender's display name from the actor cache.
    let sender_display_name = match remote_actors::find_by_actor_uri(&state.pool, actor_url).await {
        Ok(Some(ra)) => ra.display_name,
        _ => None,
    };

    // Re-read attachments for the message so the WS event carries them and
    // the recipient's UI can render them in real time without a refetch.
    let inbound_attachments: Vec<WsAttachment> = attachments::find_for_message(&state.pool, msg.id)
        .await
        .map(|rows| {
            rows.iter()
                .map(|a| WsAttachment {
                    id: a.id,
                    mime_type: a.mime_type.clone(),
                    byte_size: a.byte_size,
                    original_filename: a.original_filename.clone(),
                })
                .collect()
        })
        .unwrap_or_default();

    let event = WsEvent::NewDm(DmPayload {
        message_id: msg.id,
        conversation_id,
        kind: "dm".to_string(),
        sender_address: actor_url.to_string(),
        sender_display_name,
        content: msg.content,
        created_at: msg.created_at,
        reply_to_id,
        reply_to_content,
        reply_to_sender,
        attachments: inbound_attachments,
        client_id: None,
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
        });
    }

    state.hub.send_to_user(&recipient.id, event);

    tracing::info!(sender = %actor_url, recipient = %recipient.username, "DM stored via AP inbox");
    Ok(())
}

// ─── Update{Note} — Federated message edit ──────────────────────────────────

async fn handle_update_note(
    state: &AppState,
    body: &Value,
    obj: &Value,
    recipient: &idp_db::models::User,
) -> Result<(), OidcError> {
    let actor_url = body.get("actor").and_then(|v| v.as_str()).unwrap_or("");

    let activity_uri = obj
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let new_content = obj
        .get("content")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if activity_uri.is_empty() || new_content.is_empty() {
        return Ok(());
    }

    let updated = match messages::edit_message_by_activity_uri(
        &state.pool,
        activity_uri,
        actor_url,
        new_content,
    )
    .await
    {
        Ok(Some(m)) => m,
        Ok(None) => {
            tracing::warn!(%activity_uri, "Update{{Note}} target not found or sender mismatch");
            return Ok(());
        }
        Err(e) => return Err(OidcError::server_error(e.to_string())),
    };

    let edited_at = match updated.edited_at {
        Some(t) => t,
        None => return Ok(()),
    };

    let event = WsEvent::MessageEdited(EditedDmPayload {
        message_id: updated.id,
        new_content: updated.content,
        edited_at,
    });

    state.hub.send_to_user(&recipient.id, event.clone());

    if let Ok(json) = serde_json::to_string(&event) {
        let broker = state.broker.clone();
        let rid = recipient.id;
        tokio::spawn(async move {
            if let Err(e) = broker.publish(rid, &json).await {
                tracing::warn!(%rid, "broker publish failed for message_edited: {e}");
            }
        });
    }

    tracing::info!(
        actor = %actor_url,
        message = %updated.id,
        "message edited via AP Update{{Note}}"
    );
    Ok(())
}

// ─── Update{Person} — Profile propagation ───────────────────────────────────

async fn handle_update(
    state: &AppState,
    body: &Value,
    recipient: &idp_db::models::User,
) -> Result<(), OidcError> {
    let obj = match body.get("object") {
        Some(o) => o,
        None => return Ok(()),
    };

    let obj_type = obj
        .get("type")
        .and_then(|t| t.as_str())
        .unwrap_or("");

    if obj_type == "Note" {
        return handle_update_note(state, body, obj, recipient).await;
    }

    if obj_type != "Person" {
        return Ok(());
    }

    let actor_uri = obj
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if actor_uri.is_empty() {
        return Ok(());
    }

    let new_display_name = obj
        .get("name")
        .and_then(|v| v.as_str());
    let new_avatar_url = obj
        .get("icon")
        .and_then(|v| v.get("url"))
        .and_then(|v| v.as_str());

    // 1. Update remote_actors cache.
    remote_actors::update_profile(
        &state.pool,
        actor_uri,
        new_display_name,
        new_avatar_url,
    )
    .await
    .map_err(|e| OidcError::server_error(e.to_string()))?;

    // 2. Update friend_avatar_url on all matching friendships.
    friendships::update_friend_avatar(&state.pool, actor_uri, new_avatar_url)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    // 3. Push WebSocket event to all connected clients who have this actor as a friend.
    let owner_ids = friendships::get_owners_with_friend(&state.pool, actor_uri)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    let event = WsEvent::FriendProfileUpdated(ProfileUpdatePayload {
        actor_uri: actor_uri.to_string(),
        display_name: new_display_name.map(|s| s.to_string()),
        avatar_url: new_avatar_url.map(|s| s.to_string()),
    });

    for owner_id in owner_ids {
        state.hub.send_to_user(&owner_id, event.clone());
    }

    tracing::info!(actor_uri = %actor_uri, "profile update propagated via AP");
    Ok(())
}

// ─── Like (reaction) ─────────────────────────────────────────────────────────

/// Handle a `Like` activity: add a reaction to a message.
/// The `object` field is the activity_uri of the target message, and `content`
/// carries the emoji.
async fn handle_like(
    state: &AppState,
    body: &Value,
    recipient: &idp_db::models::User,
) -> Result<(), OidcError> {
    let actor_url = body
        .get("actor")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let target_uri = body
        .get("object")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let emoji = body
        .get("content")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if target_uri.is_empty() || emoji.is_empty() {
        tracing::warn!("Like activity missing object or content (emoji)");
        return Ok(());
    }

    // Look up the target message by its activity_uri.
    let msg = match messages::find_by_activity_uri(&state.pool, target_uri).await {
        Ok(Some(m)) => m,
        Ok(None) => {
            tracing::warn!(%target_uri, "Like target message not found");
            return Ok(());
        }
        Err(e) => return Err(OidcError::server_error(e.to_string())),
    };

    reactions::add_reaction(&state.pool, msg.id, actor_url, emoji)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    let event = WsEvent::MessageReactionAdded(ReactionPayload {
        message_id: msg.id,
        reactor_actor_uri: actor_url.to_string(),
        emoji: emoji.to_string(),
    });
    state.hub.send_to_user(&recipient.id, event);

    tracing::info!(actor = %actor_url, message = %msg.id, emoji = %emoji, "reaction added via AP Like");
    Ok(())
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Try to resolve a local actor URL (e.g. `https://base/users/alice-Ab3Kp`) to a User.
async fn local_actor(
    actor_url: &str,
    base: &str,
    pool: &sqlx::PgPool,
) -> Option<idp_db::models::User> {
    if !actor_url.starts_with(&format!("{}/users/", base)) {
        return None;
    }
    users::find_by_actor_uri(pool, actor_url)
        .await
        .ok()
        .flatten()
}

/// Parse a remote actor URL like `http://domain:port/users/username` into (username, domain).
fn parse_remote_actor_url(actor_url: &str) -> Option<(String, String)> {
    let url: url::Url = actor_url.parse().ok()?;
    let username = url.path().strip_prefix("/users/")?;
    if username.is_empty() {
        return None;
    }
    let host = url.host_str()?;
    let domain = match url.port() {
        Some(port) => format!("{}:{}", host, port),
        None => host.to_string(),
    };
    Some((username.to_string(), domain))
}

/// Fetch the remote actor's display name from their actor document.
async fn fetch_remote_display_name(actor_url: &str) -> Option<String> {
    let resp = reqwest::Client::new()
        .get(actor_url)
        .header("Accept", "application/activity+json")
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let actor: activitypub::Actor = resp.json().await.ok()?;
    Some(actor.name)
}

/// Resolve actor_uri to (username, display_name) from local users or remote cache.
async fn resolve_remote_name(state: &AppState, actor_uri: &str) -> (String, Option<String>) {
    if let Ok(Some(user)) = users::find_by_actor_uri(&state.pool, actor_uri).await {
        return (user.username, user.display_name);
    }
    let display_name = remote_actors::find_by_actor_uri(&state.pool, actor_uri).await
        .ok()
        .flatten()
        .and_then(|ra| ra.display_name);
    let username = actor_uri.rsplit('/').next().unwrap_or("unknown").to_string();
    (username, display_name)
}

/// Parse a `Note.attachment` array from an inbound `Create{Note}` and insert
/// `message_attachments` rows for each valid `Document` entry.
///
/// Validation: type=="Document", url/mediaType/name/size present and well-typed,
/// `size > 0` and `<= attachment_max_byte_size`, MIME not in the blocklist.
/// Caps the count at `attachment_max_files_per_message` (extras silently
/// ignored — the sender shouldn't have sent more, and we'd rather drop the
/// excess than reject the message).
///
/// Failures on individual entries are logged at WARN; the message itself is
/// already persisted and unaffected.
async fn persist_inbound_attachments(
    state: &AppState,
    message_id: Uuid,
    sender_actor_uri: &str,
    attachment_value: Option<&Value>,
) {
    let arr = match attachment_value.and_then(|v| v.as_array()) {
        Some(a) if !a.is_empty() => a,
        _ => return,
    };

    let max = state.config.attachment_max_files_per_message;
    let max_size = state.config.attachment_max_byte_size as i64;

    for (i, entry) in arr.iter().take(max).enumerate() {
        let obj = match entry.as_object() {
            Some(o) => o,
            None => {
                tracing::warn!(idx = i, "inbound attachment entry not an object — skipping");
                continue;
            }
        };

        let entry_type = obj.get("type").and_then(|v| v.as_str()).unwrap_or("");
        if entry_type != "Document" {
            tracing::warn!(idx = i, %entry_type, "inbound attachment not a Document — skipping");
            continue;
        }

        let url = match obj.get("url").and_then(|v| v.as_str()) {
            Some(u) if !u.is_empty() => u,
            _ => {
                tracing::warn!(idx = i, "inbound attachment missing url — skipping");
                continue;
            }
        };
        let mime = match obj.get("mediaType").and_then(|v| v.as_str()) {
            Some(m) if !m.is_empty() => m,
            _ => {
                tracing::warn!(idx = i, "inbound attachment missing mediaType — skipping");
                continue;
            }
        };
        let filename = obj
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("attachment");
        let byte_size = match obj.get("size").and_then(|v| v.as_i64()) {
            Some(s) if s > 0 && s <= max_size => s,
            Some(s) => {
                tracing::warn!(
                    idx = i, size = s, max = max_size,
                    "inbound attachment size out of range — skipping"
                );
                continue;
            }
            None => {
                tracing::warn!(idx = i, "inbound attachment missing size — skipping");
                continue;
            }
        };

        let mime_lower = mime.to_lowercase();
        if state
            .config
            .attachment_blocked_mimes
            .iter()
            .any(|b| b == &mime_lower)
        {
            tracing::warn!(idx = i, %mime, "inbound attachment MIME blocklisted — skipping");
            continue;
        }

        let id = Uuid::new_v4();
        let storage_key = id.to_string();
        if let Err(e) = attachments::insert_remote(
            &state.pool,
            id,
            message_id,
            sender_actor_uri,
            &storage_key,
            mime,
            byte_size,
            filename,
            url,
        )
        .await
        {
            tracing::warn!(idx = i, "failed to persist inbound attachment: {e}");
        }
    }
}
