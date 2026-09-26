//! POST /users/:username/inbox
//!
//! Receives ActivityPub activities from remote and local servers.
//! Supported activities:
//!   - Follow         → creates a pending friendship
//!   - Accept{Follow} → marks a friendship as accepted
//!   - Reject{Follow} → deletes the inbox owner's pending request
//!   - Undo{Follow}   → deletes the friendship
//!   - Create{Note}   → MLS-only after Phase 3: routes to `mls::handle_inbound_mls_note`
//!     (any Note without `mediaType: application/mls` is rejected)
//!   - Update{Note}   → MLS-only edit: replaces the row's `mls_ciphertext`
//!   - Update{Person} → updates remote_actors cache + propagates profile changes
//!
//! `Like` / `Undo{Like}` are gone — reactions are now MLS application
//! messages of `kind = "reaction"` inside the encrypted body.

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde_json::Value;
use uuid::Uuid;

use idp_db::repos::{attachments, conversations, friendships, messages, remote_actors, users};

use idp_realtime::{EditedDmPayload, FriendshipPayload, ProfileUpdatePayload, WsEvent};

use idp_state::{AppState, OidcError};

use crate::http_signature::{verify_body_digest, verify_http_signature};

/// POST /users/:slug/inbox
#[tracing::instrument(skip_all, fields(slug = %slug))]
pub async fn post_inbox(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, OidcError> {
    // Authenticate the peer before touching any state. `Bytes` rather than
    // `Json` because the digest must be taken over the bytes as received —
    // re-serialising a parsed Value would not reproduce them.
    let signature_path = format!("/users/{}/inbox", slug);
    let key_id = verify_http_signature(&state.key_cache, &headers, "post", &signature_path).await?;
    verify_body_digest(&headers, &body)?;

    let body: Value = serde_json::from_slice(&body)
        .map_err(|e| OidcError::invalid_request(format!("malformed activity JSON: {e}")))?;

    verify_actor_binding(&key_id, &body)?;

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
        "Accept" => handle_accept(&state, &body, &recipient).await?,
        "Reject" => handle_reject(&state, &body, &recipient).await?,
        "Undo" => handle_undo(&state, &body, &recipient).await?,
        "Create" => handle_create(&state, &body, &recipient).await?,
        "Update" => handle_update(&state, &body, &recipient).await?,
        other => {
            tracing::warn!(activity_type = %other, "unhandled activity type in inbox");
        }
    }

    Ok(StatusCode::ACCEPTED)
}

/// The activity's `actor`, which AP allows to be either a URI or an embedded object.
fn activity_actor(body: &Value) -> Option<&str> {
    match body.get("actor")? {
        Value::String(s) => Some(s.as_str()),
        Value::Object(o) => o.get("id").and_then(|v| v.as_str()),
        _ => None,
    }
}

/// Reject an activity whose `actor` is not the key that signed the request.
///
/// A verified signature only proves *some* actor signed this; without this
/// binding any federated peer could post activities on behalf of anyone.
fn verify_actor_binding(key_id: &str, body: &Value) -> Result<(), OidcError> {
    let signer = key_id.split('#').next().unwrap_or_default();
    let claimed = activity_actor(body)
        .ok_or_else(|| OidcError::invalid_request("activity missing actor field"))?;
    if signer != claimed {
        tracing::warn!(%signer, %claimed, "inbox activity actor does not match signer");
        return Err(OidcError::access_denied(
            "activity actor does not match the signing key",
        ));
    }
    Ok(())
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

    let recipient_actor_uri = recipient
        .actor_uri
        .as_deref()
        .ok_or_else(|| OidcError::server_error("Recipient has no actor_uri"))?;

    // Check if this is a local actor.
    let base = state.config.issuer();
    if let Some(follower) = local_actor(actor_url, &base, &state.pool).await {
        // Local-to-local: insert both rows as `pending` and notify the
        // recipient with a single `FriendRequest`. The DM conversation is
        // minted later by `accept_friendship` once the recipient consents.
        let follower_uri = follower
            .actor_uri
            .as_deref()
            .ok_or_else(|| OidcError::server_error("Follower has no actor_uri"))?;

        // Follower → recipient
        friendships::create_friendship(
            &state.pool,
            follower.id,
            recipient_actor_uri,
            recipient.avatar_url.as_deref(),
            "outgoing",
        )
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

        // Recipient → follower — this is the row the recipient will accept.
        let recipient_row = friendships::create_friendship(
            &state.pool,
            recipient.id,
            follower_uri,
            follower.avatar_url.as_deref(),
            "incoming",
        )
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

        state.hub.send_to_user(
            &recipient.id,
            WsEvent::FriendRequest(FriendshipPayload {
                friendship_id: recipient_row.id,
                actor_uri: follower_uri.to_string(),
                username: follower.username.clone(),
                display_name: follower.display_name.clone(),
                conversation_id: None,
            }),
        );

        tracing::info!(
            follower = %follower.username,
            recipient = %recipient.username,
            "local friend request notified (pending)"
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
        let friendship =
            friendships::create_friendship(&state.pool, recipient.id, actor_url, None, "incoming")
                .await
                .map_err(|e| OidcError::server_error(e.to_string()))?;

        // Notify inbox owner of pending friend request. No conversation
        // yet — created on accept.
        state.hub.send_to_user(
            &recipient.id,
            WsEvent::FriendRequest(FriendshipPayload {
                friendship_id: friendship.id,
                actor_uri: actor_url.to_string(),
                username: remote_username.clone(),
                display_name,
                conversation_id: None,
            }),
        );

        tracing::info!(actor = %actor_url, recipient = %recipient.username, "remote friend request notified");
    }

    Ok(())
}

// ─── Accept ──────────────────────────────────────────────────────────────────

/// The accepter answered a friend request the inbox owner sent. The row is keyed
/// on the inbox the Accept was delivered to, never on a field of the
/// activity, so a peer cannot accept on behalf of other local users.
async fn handle_accept(
    state: &AppState,
    body: &Value,
    recipient: &idp_db::models::User,
) -> Result<(), OidcError> {
    let accepter_uri = body.get("actor").and_then(|v| v.as_str()).unwrap_or("");

    // Pina'i extension: the accepter's IdP minted the DM conversation
    // alongside `set_status('accepted')` and surfaces its id here so
    // both sides agree on `conversations.id`. Missing → fall back to
    // `get_or_create_dm` (pre-refactor peer) which is a safe
    // degradation: the two IdPs end up with different ids, exactly
    // matching the existing pre-refactor state.
    let advertised_conv_id = body
        .get("conversationId")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok());

    let recipient_actor_uri = recipient
        .actor_uri
        .as_deref()
        .ok_or_else(|| OidcError::server_error("Recipient has no actor_uri"))?;

    // Only a request the recipient sent: an Accept for one the peer sent
    // would let it consent on the recipient's behalf.
    let friendship = friendships::find_by_owner_and_uri(&state.pool, recipient.id, accepter_uri)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    let Some(friendship) =
        friendship.filter(|f| f.status == "pending" && f.direction == "outgoing")
    else {
        tracing::debug!(accepter = %accepter_uri, recipient = %recipient.username, "Accept with no outgoing request");
        return Ok(());
    };

    friendships::set_status(&state.pool, friendship.id, "accepted")
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    let conversation_id =
        create_local_dm_for_accept(state, advertised_conv_id, recipient_actor_uri, accepter_uri)
            .await?;

    let (username, display_name) = resolve_remote_name(state, accepter_uri).await;
    state.hub.send_to_user(
        &recipient.id,
        WsEvent::FriendAccepted(FriendshipPayload {
            friendship_id: friendship.id,
            actor_uri: accepter_uri.to_string(),
            username,
            display_name,
            conversation_id: Some(conversation_id),
        }),
    );

    // Wire the new remote friend into batch presence polling.
    if let Some(registry) = &state.remote_registry {
        registry.register_friend(accepter_uri, &state.config.issuer());
    }

    tracing::info!(user = %recipient.username, accepter = %accepter_uri, %conversation_id, "friend request accepted via AP");
    Ok(())
}

/// Materialise the local DM row for a friendship that just got accepted via AP.
/// If the accepter advertised a `conversationId` we honour it (so both sides
/// agree on the row id); otherwise fall back to `get_or_create_dm` for
/// safe degradation against pre-refactor peers.
async fn create_local_dm_for_accept(
    state: &AppState,
    advertised: Option<Uuid>,
    owner_uri: &str,
    accepter_uri: &str,
) -> Result<Uuid, OidcError> {
    let result = match advertised {
        Some(id) => {
            conversations::get_or_create_dm_with_id(&state.pool, id, owner_uri, accepter_uri).await
        }
        None => conversations::get_or_create_dm(&state.pool, owner_uri, accepter_uri).await,
    };
    let (conv_id, _created) = result.map_err(|e| OidcError::server_error(e.to_string()))?;
    Ok(conv_id)
}

// ─── Reject ──────────────────────────────────────────────────────────────────

/// The rejecter declined a friend request the inbox owner sent. Only that one
/// row is touched: it is keyed on the inbox the Reject was delivered to,
/// never on a field of the activity, so a peer cannot drop other users'
/// requests. The owner is not notified — a declined request just stops
/// existing.
async fn handle_reject(
    state: &AppState,
    body: &Value,
    recipient: &idp_db::models::User,
) -> Result<(), OidcError> {
    let rejecter_uri = body.get("actor").and_then(|v| v.as_str()).unwrap_or("");

    let friendship = friendships::find_by_owner_and_uri(&state.pool, recipient.id, rejecter_uri)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    let Some(friendship) =
        friendship.filter(|f| f.status == "pending" && f.direction == "outgoing")
    else {
        tracing::debug!(rejecter = %rejecter_uri, recipient = %recipient.username, "Reject with no outgoing request");
        return Ok(());
    };

    friendships::delete_friendship(&state.pool, recipient.id, rejecter_uri)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    tracing::info!(friendship_id = %friendship.id, "friend request rejected via AP");
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
        _ => Ok(()),
    }
}

async fn handle_undo_follow(
    state: &AppState,
    body: &Value,
    recipient: &idp_db::models::User,
) -> Result<(), OidcError> {
    let actor_url = body.get("actor").and_then(|v| v.as_str()).unwrap_or("");

    let recipient_actor_uri = recipient.actor_uri.as_deref().unwrap_or("");

    // Remove the friendship: recipient → actor.
    let Some(friendship) = friendships::find_by_owner_and_uri(&state.pool, recipient.id, actor_url)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
    else {
        tracing::debug!(actor = %actor_url, recipient = %recipient.username, "Undo{{Follow}} with no friendship");
        return Ok(());
    };
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

    // Lets the recipient's clients drop the actor from their list. Clients
    // refresh on it silently — an unfriend is never announced.
    let (username, display_name) = resolve_remote_name(state, actor_url).await;
    state.hub.send_to_user(
        &recipient.id,
        WsEvent::FriendRemoved(FriendshipPayload {
            friendship_id: friendship.id,
            actor_uri: actor_url.to_string(),
            username,
            display_name,
            conversation_id: None,
        }),
    );

    crate::friendship::release_remote_presence(state, actor_url).await;

    tracing::info!(actor = %actor_url, recipient = %recipient.username, "unfriended via AP Undo");
    Ok(())
}

// ─── Create{Note} — MLS-only after Phase 3 ──────────────────────────────────

async fn handle_create(
    state: &AppState,
    body: &Value,
    recipient: &idp_db::models::User,
) -> Result<(), OidcError> {
    let obj = match body.get("object") {
        Some(o) => o,
        None => return Ok(()),
    };

    let obj_type = obj.get("type").and_then(|t| t.as_str()).unwrap_or("");

    if obj_type != "Note" {
        return Ok(());
    }

    // After Phase 3 every DM-bearing Note must be MLS-flavoured. Reject
    // anything else — peers running pre-MLS builds can't interop.
    let media_type = obj.get("mediaType").and_then(|m| m.as_str()).unwrap_or("");
    if media_type != "application/mls" {
        tracing::warn!(
            recipient = %recipient.username,
            %media_type,
            "rejecting Create{{Note}} without `mediaType: application/mls` — peer must run an MLS-capable build"
        );
        return Ok(());
    }

    crate::mls::handle_inbound_mls_note(state, body, obj, recipient).await
}

// ─── Update{Note} — Federated MLS edit ──────────────────────────────────────

async fn handle_update_note(
    state: &AppState,
    body: &Value,
    obj: &Value,
    recipient: &idp_db::models::User,
) -> Result<(), OidcError> {
    let actor_url = body.get("actor").and_then(|v| v.as_str()).unwrap_or("");

    // Same MLS-only gate as Create{Note}: a peer running a pre-MLS build
    // can't produce an Update we can apply, since the row's body is opaque
    // ciphertext now.
    let media_type = obj.get("mediaType").and_then(|m| m.as_str()).unwrap_or("");
    if media_type != "application/mls" {
        tracing::warn!(
            %media_type,
            "rejecting Update{{Note}} without `mediaType: application/mls`"
        );
        return Ok(());
    }

    let activity_uri = obj.get("id").and_then(|v| v.as_str()).unwrap_or("");

    let new_b64 = obj.get("content").and_then(|v| v.as_str()).unwrap_or("");

    if activity_uri.is_empty() || new_b64.is_empty() {
        return Ok(());
    }

    let new_mls_ciphertext = match B64.decode(new_b64) {
        Ok(b) if !b.is_empty() => b,
        _ => {
            tracing::warn!(%activity_uri, "Update{{Note}} content is not valid non-empty base64");
            return Ok(());
        }
    };

    let updated = match messages::edit_message_by_activity_uri(
        &state.pool,
        activity_uri,
        actor_url,
        &new_mls_ciphertext,
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
        new_mls_ciphertext: B64.encode(&updated.mls_ciphertext),
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
        "message edited via AP Update{{Note}} (MLS)"
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

    let obj_type = obj.get("type").and_then(|t| t.as_str()).unwrap_or("");

    if obj_type == "Note" {
        return handle_update_note(state, body, obj, recipient).await;
    }

    if obj_type != "Person" {
        return Ok(());
    }

    let actor_uri = obj.get("id").and_then(|v| v.as_str()).unwrap_or("");

    if actor_uri.is_empty() {
        return Ok(());
    }

    let new_display_name = obj.get("name").and_then(|v| v.as_str());
    let new_avatar_url = obj
        .get("icon")
        .and_then(|v| v.get("url"))
        .and_then(|v| v.as_str());

    // 1. Update remote_actors cache.
    remote_actors::update_profile(&state.pool, actor_uri, new_display_name, new_avatar_url)
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
pub(crate) async fn persist_inbound_attachments(
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
                    idx = i,
                    size = s,
                    max = max_size,
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

        // Use the sender's attachment UUID (embedded in the
        // `<issuer>/api/attachments/<uuid>/content` URL) as the row id
        // on this IdP too. The client puts the per-attachment AES key
        // + nonce in the encrypted MLS body keyed by that same UUID
        // (it's the `AttachmentBlobKey.id`), so if we picked a fresh
        // random UUID here the recipient's `attachmentKeys[a.id]`
        // lookup would always miss → realMime falls back to the
        // server-visible placeholder `"application/octet-stream"` →
        // images/GIFs render as a "FILE" tile instead of an image.
        // Falls back to a fresh UUID only if the URL doesn't carry
        // one in the expected shape.
        let id = extract_attachment_uuid(url).unwrap_or_else(Uuid::new_v4);
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

/// Pull the trailing UUID out of an attachment URL of shape
/// `<issuer>/api/attachments/<uuid>/content`. Used to bridge attachment
/// row ids across IdPs so the recipient's `AttachmentBlobKey.id` (set
/// by the sender, embedded in the encrypted MLS body) matches the
/// wire-shape `Attachment.id` returned by the recipient's REST surface.
fn extract_attachment_uuid(url: &str) -> Option<Uuid> {
    let trimmed = url.strip_suffix("/content").unwrap_or(url);
    let last_segment = trimmed.rsplit('/').next()?;
    Uuid::parse_str(last_segment).ok()
}

#[cfg(test)]
mod tests;
