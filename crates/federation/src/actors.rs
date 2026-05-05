//! Helpers for resolving actor metadata (display names, profile lookups).

use sqlx::PgPool;

use idp_db::repos::{remote_actors, users};

/// Look up the display name for an actor URI.
/// Checks local users first, then the remote actors cache.
/// For local users, falls back to `username` if `display_name` is unset.
pub async fn display_name_for_actor(pool: &PgPool, actor_uri: &str) -> Option<String> {
    if let Ok(Some(user)) = users::find_by_actor_uri(pool, actor_uri).await {
        return Some(user.display_name.unwrap_or(user.username));
    }
    if let Ok(Some(ra)) = remote_actors::find_by_actor_uri(pool, actor_uri).await {
        return ra.display_name;
    }
    None
}
