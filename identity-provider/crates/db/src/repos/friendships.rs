use sqlx::PgPool;
use uuid::Uuid;

use crate::models::{FriendListEntry, Friendship};

/// Get the full friends list using a JOIN across users and remote_actors.
/// Returns accepted friendships only.
pub async fn get_friends(
    pool: &PgPool,
    owner_user_id: Uuid,
) -> Result<Vec<FriendListEntry>, sqlx::Error> {
    sqlx::query_as::<_, FriendListEntry>(
        r#"
        SELECT
          u.username                               AS username,
          COALESCE(u.display_name, ra.display_name) AS display_name,
          f.friend_avatar_url                       AS avatar_url,
          f.friend_actor_uri,
          COALESCE(ra.instance, 'local')            AS instance
        FROM friendships f
        LEFT JOIN users u          ON f.friend_actor_uri = u.actor_uri
        LEFT JOIN remote_actors ra ON f.friend_actor_uri = ra.actor_uri
        WHERE f.owner_user_id = $1
          AND f.status = 'accepted'
        "#,
    )
    .bind(owner_user_id)
    .fetch_all(pool)
    .await
}

/// Batch-update friend_avatar_url on all friendship rows for a given actor.
/// Called when a profile update is received (local or remote).
pub async fn update_friend_avatar(
    pool: &PgPool,
    friend_actor_uri: &str,
    avatar_url: Option<&str>,
) -> Result<Vec<Friendship>, sqlx::Error> {
    sqlx::query_as::<_, Friendship>(
        r#"
        UPDATE friendships
        SET friend_avatar_url = $2, updated_at = now()
        WHERE friend_actor_uri = $1
        RETURNING *
        "#,
    )
    .bind(friend_actor_uri)
    .bind(avatar_url)
    .fetch_all(pool)
    .await
}

/// Find all owner_user_ids who have this actor_uri as a friend (accepted).
/// Used to push WebSocket profile update events.
pub async fn get_owners_with_friend(
    pool: &PgPool,
    friend_actor_uri: &str,
) -> Result<Vec<Uuid>, sqlx::Error> {
    let rows = sqlx::query_scalar::<_, Uuid>(
        "SELECT owner_user_id FROM friendships WHERE friend_actor_uri = $1 AND status = 'accepted'",
    )
    .bind(friend_actor_uri)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Get all distinct friend actor URIs from accepted friendships.
/// Used to populate the remote presence registry on startup.
pub async fn get_all_friend_actor_uris(pool: &PgPool) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar::<_, String>(
        "SELECT DISTINCT friend_actor_uri FROM friendships WHERE status = 'accepted'",
    )
    .fetch_all(pool)
    .await
}

/// A remote friend's inbox — the only fields needed for outbound AP delivery.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RemoteFriendInbox {
    pub actor_uri: String,
    pub inbox_url: Option<String>,
}

/// Distinct remote friends of an owner, with their cached inbox URLs.
///
/// "Remote" is encoded by the INNER JOIN on `remote_actors` — local friends
/// have no row there. The `inbox_url` may be NULL if WebFinger never resolved
/// it; the caller is expected to skip or refetch in that case.
pub async fn list_remote_friends_with_inbox(
    pool: &PgPool,
    owner_user_id: Uuid,
) -> Result<Vec<RemoteFriendInbox>, sqlx::Error> {
    sqlx::query_as::<_, RemoteFriendInbox>(
        r#"
        SELECT DISTINCT f.friend_actor_uri AS actor_uri,
                        ra.inbox_url       AS inbox_url
        FROM friendships f
        INNER JOIN remote_actors ra ON f.friend_actor_uri = ra.actor_uri
        WHERE f.owner_user_id = $1
          AND f.status = 'accepted'
        "#,
    )
    .bind(owner_user_id)
    .fetch_all(pool)
    .await
}
