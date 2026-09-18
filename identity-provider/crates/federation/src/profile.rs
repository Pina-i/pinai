//! Outbound profile-update propagation.
//!
//! When a local user's display_name or avatar changes, fan the new profile
//! out to:
//!
//! - **Local friends** — push a `FriendProfileUpdated` WS event to every
//!   local user who has this actor as an accepted friend.
//! - **Remote friends** — POST a signed `Update{Person}` activity to each
//!   distinct remote inbox via the existing AP delivery path.
//!
//! Delivery is best-effort and inline (`tokio::spawn`). A missed delivery
//! self-heals via the `remote_actors.fetched_at` TTL on the recipient side
//! — `Update{Person}` is idempotent, so re-running it after a TTL re-fetch
//! produces the same end state. See `identity-provider/specs/01-identity-federation.md § Federation delivery
//! semantics` for the rationale behind not having a durable outbox.

use activitypub::Activity;
use idp_db::repos::{friendships, users};
use idp_realtime::{ProfileUpdatePayload, WsEvent};
use idp_state::AppState;
use uuid::Uuid;

use crate::delivery;

/// Fan a profile update for `user_id` out to local + remote friends.
///
/// Reads the user fresh from the DB, so the caller can invoke this after any
/// successful profile mutation without threading the new values through.
#[tracing::instrument(skip(state))]
pub async fn propagate_profile_update(state: &AppState, user_id: Uuid) {
    let user = match users::find_by_id(&state.pool, user_id).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            tracing::warn!(user_id = %user_id, "profile update: user not found");
            return;
        }
        Err(e) => {
            tracing::error!(user_id = %user_id, error = %e, "profile update: user fetch failed");
            return;
        }
    };

    let actor_uri = match user.actor_uri.as_deref() {
        Some(uri) if !uri.is_empty() => uri.to_string(),
        _ => {
            tracing::warn!(user_id = %user_id, "profile update: user has no actor_uri");
            return;
        }
    };

    // ── 1. Local fanout ─────────────────────────────────────────────────
    match friendships::get_owners_with_friend(&state.pool, &actor_uri).await {
        Ok(owners) => {
            let event = WsEvent::FriendProfileUpdated(ProfileUpdatePayload {
                actor_uri: actor_uri.clone(),
                display_name: user.display_name.clone(),
                avatar_url: user.avatar_url.clone(),
            });
            for owner_id in owners {
                state.hub.send_to_user(&owner_id, event.clone());
            }
        }
        Err(e) => {
            tracing::error!(error = %e, "profile update: local fanout query failed");
        }
    }

    // ── 2. Remote fanout via signed Update{Person} ──────────────────────
    let remote_friends =
        match friendships::list_remote_friends_with_inbox(&state.pool, user_id).await {
            Ok(list) => list,
            Err(e) => {
                tracing::error!(error = %e, "profile update: remote friend lookup failed");
                return;
            }
        };

    if remote_friends.is_empty() {
        return;
    }

    let activity = Activity::update_person(
        &actor_uri,
        &user.username,
        user.display_name.as_deref(),
        user.avatar_url.as_deref(),
    );

    let activity_value = match serde_json::to_value(&activity) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = %e, "profile update: activity serialization failed");
            return;
        }
    };

    for friend in remote_friends {
        let Some(inbox_url) = friend.inbox_url else {
            tracing::debug!(
                actor_uri = %friend.actor_uri,
                "profile update: skipping remote friend (no cached inbox_url)"
            );
            continue;
        };

        let state_clone = state.clone();
        let activity_clone = activity_value.clone();
        let sender_username = user.username.clone();
        tokio::spawn(async move {
            if let Err(e) = delivery::deliver_activity(
                &state_clone,
                &inbox_url,
                &activity_clone,
                &sender_username,
            )
            .await
            {
                tracing::warn!(
                    %inbox_url,
                    error = ?e,
                    "profile update: AP delivery failed (will self-heal via fetched_at TTL)"
                );
            }
        });
    }

    tracing::info!(
        actor_uri = %actor_uri,
        "profile update propagation initiated"
    );
}
