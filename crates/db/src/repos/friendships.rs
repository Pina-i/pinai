use sqlx::PgPool;
use uuid::Uuid;

use crate::models::{FriendListEntry, Friendship};

/// Create a friendship row (status defaults to 'pending').
pub async fn create_friendship(
    pool: &PgPool,
    owner_user_id: Uuid,
    friend_actor_uri: &str,
    friend_avatar_url: Option<&str>,
) -> Result<Friendship, sqlx::Error> {
    sqlx::query_as::<_, Friendship>(
        r#"
        INSERT INTO friendships (owner_user_id, friend_actor_uri, friend_avatar_url)
        VALUES ($1, $2, $3)
        ON CONFLICT (owner_user_id, friend_actor_uri)
        DO UPDATE SET status = 'pending', updated_at = now()
        RETURNING *
        "#,
    )
    .bind(owner_user_id)
    .bind(friend_actor_uri)
    .bind(friend_avatar_url)
    .fetch_one(pool)
    .await
}

/// Update a friendship's status ('pending' → 'accepted').
pub async fn set_status(
    pool: &PgPool,
    friendship_id: Uuid,
    status: &str,
) -> Result<Option<Friendship>, sqlx::Error> {
    sqlx::query_as::<_, Friendship>(
        "UPDATE friendships SET status = $1, updated_at = now() WHERE id = $2 RETURNING *",
    )
    .bind(status)
    .bind(friendship_id)
    .fetch_optional(pool)
    .await
}

/// Delete a friendship (unfriend).
pub async fn delete_friendship(
    pool: &PgPool,
    owner_user_id: Uuid,
    friend_actor_uri: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "DELETE FROM friendships WHERE owner_user_id = $1 AND friend_actor_uri = $2",
    )
    .bind(owner_user_id)
    .bind(friend_actor_uri)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

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

/// Pending friend requests for this user.
pub async fn get_pending_requests(
    pool: &PgPool,
    owner_user_id: Uuid,
) -> Result<Vec<Friendship>, sqlx::Error> {
    sqlx::query_as::<_, Friendship>(
        "SELECT * FROM friendships WHERE owner_user_id = $1 AND status = 'pending' ORDER BY created_at DESC",
    )
    .bind(owner_user_id)
    .fetch_all(pool)
    .await
}

pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<Option<Friendship>, sqlx::Error> {
    sqlx::query_as::<_, Friendship>("SELECT * FROM friendships WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
}

pub async fn find_by_owner_and_uri(
    pool: &PgPool,
    owner_user_id: Uuid,
    friend_actor_uri: &str,
) -> Result<Option<Friendship>, sqlx::Error> {
    sqlx::query_as::<_, Friendship>(
        "SELECT * FROM friendships WHERE owner_user_id = $1 AND friend_actor_uri = $2",
    )
    .bind(owner_user_id)
    .bind(friend_actor_uri)
    .fetch_optional(pool)
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
