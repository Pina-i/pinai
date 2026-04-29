//! Fan-out logic for presence and typing events to local WebSocket connections.

use std::sync::Arc;

use idp_db::repos::{conversations, friendships, users};
use idp_db::PgPool;
use tracing::warn;
use uuid::Uuid;

use crate::ws::events::{PresenceUpdatePayload, TypingPayload, WsEvent};
use crate::ws::WsHub;

use super::types::{PresenceEvent, TypingEvent};

/// Fan out a presence event to all local friends of the actor.
///
/// Looks up which local users have this actor as an accepted friend,
/// then pushes a `PresenceUpdate` WsEvent to each via the hub.
pub async fn fanout_presence(event: &PresenceEvent, pool: &PgPool, hub: &Arc<WsHub>) {
    let local_user_ids = match friendships::get_owners_with_friend(pool, &event.actor_uri).await {
        Ok(ids) => ids,
        Err(e) => {
            warn!(actor_uri = %event.actor_uri, "failed to look up friends for presence fanout: {e}");
            return;
        }
    };

    if local_user_ids.is_empty() {
        return;
    }

    let ws_event = WsEvent::PresenceUpdate(PresenceUpdatePayload {
        actor_uri: event.actor_uri.clone(),
        state: event.event.to_string(),
        timestamp: event.timestamp.clone(),
    });

    for user_id in &local_user_ids {
        hub.send_to_user(user_id, ws_event.clone());
    }
}

/// Fan out a typing event to all local members of the conversation except the sender.
///
/// Looks up conversation members, resolves each actor_uri to a local user UUID,
/// then pushes a `Typing` WsEvent via the hub. Remote members are skipped.
pub async fn fanout_typing(event: &TypingEvent, pool: &PgPool, hub: &Arc<WsHub>) {
    let members = match conversations::get_members(pool, event.conversation_id).await {
        Ok(m) => m,
        Err(e) => {
            warn!(conversation_id = %event.conversation_id, "failed to look up members for typing fanout: {e}");
            return;
        }
    };

    let ws_event = WsEvent::Typing(TypingPayload {
        actor_uri: event.actor_uri.clone(),
        conversation_id: event.conversation_id,
        timestamp: event.timestamp.clone(),
    });

    for member in &members {
        if member.actor_uri == event.actor_uri {
            continue;
        }
        if let Ok(Some(user)) = users::find_by_actor_uri(pool, &member.actor_uri).await {
            hub.send_to_user(&user.id, ws_event.clone());
        }
    }
}

/// Resolve a local user UUID from an actor_uri. Returns None for remote actors.
pub async fn resolve_local_user_id(pool: &PgPool, actor_uri: &str) -> Option<Uuid> {
    users::find_by_actor_uri(pool, actor_uri)
        .await
        .ok()
        .flatten()
        .map(|u| u.id)
}
