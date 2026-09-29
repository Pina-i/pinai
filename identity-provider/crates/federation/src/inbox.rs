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
use domain::identity::ActorUri;
use domain::social::SocialError;
use domain::ConversationId;
use serde_json::Value;
use uuid::Uuid;

use idp_db::repos::{friendships, remote_actors, users};

use idp_realtime::{ProfileUpdatePayload, WsEvent};

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

// ─── Friendship activities ───────────────────────────────────────────────────
//
// Each is keyed on the inbox it was delivered to, never on a field of the activity, so a peer
// cannot act on behalf of other local users. A redelivery is a no-op.

/// The activity's actor, already bound to the signing key by `verify_actor_binding`.
fn actor_uri(body: &Value) -> Result<ActorUri, OidcError> {
    activity_actor(body)
        .and_then(|actor| ActorUri::parse(actor).ok())
        .ok_or_else(|| OidcError::invalid_request("Cannot parse remote actor URL"))
}

fn friendship_refused(error: SocialError) -> OidcError {
    match error {
        // The follower's URI names no account this instance can address.
        SocialError::UserNotFound => OidcError::invalid_request("Cannot parse remote actor URL"),
        SocialError::PeerNotAllowed(reason) => OidcError::access_denied(reason),
        SocialError::Unexpected(e) => {
            tracing::error!(error = ?e, "inbox friendship activity failed");
            OidcError {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                error: "server_error",
                error_description: "internal error".to_owned(),
            }
        }
        other => OidcError::invalid_request(other.to_string()),
    }
}

async fn handle_follow(
    state: &AppState,
    body: &Value,
    recipient: &idp_db::models::User,
) -> Result<(), OidcError> {
    state
        .receive_follow
        .execute(recipient.id.into(), actor_uri(body)?)
        .await
        .map_err(friendship_refused)
}

/// Carries the Pina'i `conversationId` extension: the DM id the accepter's instance minted.
async fn handle_accept(
    state: &AppState,
    body: &Value,
    recipient: &idp_db::models::User,
) -> Result<(), OidcError> {
    let advertised = body
        .get("conversationId")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok())
        .map(ConversationId::from);
    state
        .receive_accept
        .execute(recipient.id.into(), actor_uri(body)?, advertised)
        .await
        .map_err(friendship_refused)
}

async fn handle_reject(
    state: &AppState,
    body: &Value,
    recipient: &idp_db::models::User,
) -> Result<(), OidcError> {
    state
        .receive_reject
        .execute(recipient.id.into(), actor_uri(body)?)
        .await
        .map_err(friendship_refused)
}

async fn handle_undo(
    state: &AppState,
    body: &Value,
    recipient: &idp_db::models::User,
) -> Result<(), OidcError> {
    let undone = body
        .get("object")
        .and_then(|o| o.get("type"))
        .and_then(|t| t.as_str());
    if undone != Some("Follow") {
        return Ok(());
    }
    state
        .receive_undo_follow
        .execute(recipient.id.into(), actor_uri(body)?)
        .await
        .map_err(friendship_refused)
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

    let Ok(sender) = domain::identity::ActorUri::parse(actor_url) else {
        tracing::warn!(%activity_uri, "Update{{Note}} from an actor that is no actor URI");
        return Ok(());
    };
    let ciphertext = domain::messaging::MlsCiphertext::parse(new_mls_ciphertext).map_err(|e| {
        OidcError::invalid_request(format!("Update{{Note}} `content` {}", e.reason))
    })?;
    state
        .receive_edit
        .execute(application::messaging::IncomingEdit {
            recipient: recipient.id.into(),
            sender,
            activity_uri: activity_uri.to_owned(),
            ciphertext,
        })
        .await
        .map_err(crate::mls::messaging_refused)
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

#[cfg(test)]
mod tests;
