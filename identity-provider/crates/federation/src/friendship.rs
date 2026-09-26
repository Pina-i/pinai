//! Friendship side effects shared by the social REST handlers and the inbox:
//! delivering a friendship activity to a peer, and presence polling cleanup.

use activitypub::Activity;
use idp_db::models::RemoteActor;
use idp_db::repos::friendships;
use idp_state::AppState;

use crate::delivery;

/// The inbox of a cached remote actor: the one WebFinger resolved, or the
/// conventional `{actor}/inbox` when none was cached (an actor first seen
/// through an inbound `Follow` carries no inbox).
pub fn remote_inbox(remote: &RemoteActor) -> String {
    remote
        .inbox_url
        .clone()
        .unwrap_or_else(|| format!("{}/inbox", remote.actor_uri))
}

/// Deliver a friendship activity (`Reject`, `Undo{Follow}`) without failing
/// the request that triggered it.
///
/// The local change is already committed and is what the user asked for; a
/// peer that cannot be reached keeps its own row until the relationship is
/// touched again.
pub async fn deliver_best_effort(
    state: &AppState,
    remote: &RemoteActor,
    activity: &Activity,
    sender_username: &str,
) {
    let inbox_url = remote_inbox(remote);
    let result = match serde_json::to_value(activity) {
        Ok(json) => delivery::deliver_activity(state, &inbox_url, &json, sender_username).await,
        Err(e) => {
            tracing::warn!(error = %e, "friendship activity serialization failed");
            return;
        }
    };
    if let Err(e) = result {
        tracing::warn!(
            %inbox_url,
            activity_type = %activity.activity_type,
            error = ?e,
            "friendship activity delivery failed"
        );
    }
}

/// Stop batch-polling a remote actor's presence once no local user still
/// has them as an accepted friend.
///
/// The registry is per-IdP, not per-user: unregistering on one user's
/// unfriend would blank the actor's presence for every other local friend.
pub async fn release_remote_presence(state: &AppState, actor_uri: &str) {
    let Some(registry) = &state.remote_registry else {
        return;
    };
    match friendships::get_owners_with_friend(&state.pool, actor_uri).await {
        Ok(owners) if owners.is_empty() => {
            registry.unregister_friend(actor_uri, &state.config.issuer());
        }
        Ok(_) => {}
        Err(e) => tracing::warn!(error = %e, %actor_uri, "presence release lookup failed"),
    }
}

#[cfg(test)]
mod tests;
