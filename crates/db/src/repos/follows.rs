use sqlx::PgPool;
use uuid::Uuid;

use crate::models::Follow;

pub async fn send_follow_request(
    pool: &PgPool,
    follower_id: Uuid,
    following_id: Uuid,
    ap_activity_id: Option<&str>,
) -> Result<Follow, sqlx::Error> {
    sqlx::query_as::<_, Follow>(
        r#"
        INSERT INTO follows (follower_id, following_id, state, ap_activity_id)
        VALUES ($1, $2, 'pending', $3)
        ON CONFLICT (follower_id, following_id)
        DO UPDATE SET state = 'pending', ap_activity_id = EXCLUDED.ap_activity_id
        RETURNING *
        "#,
    )
    .bind(follower_id)
    .bind(following_id)
    .bind(ap_activity_id)
    .fetch_one(pool)
    .await
}

pub async fn set_follow_state(
    pool: &PgPool,
    follow_id: Uuid,
    state: &str,
) -> Result<Option<Follow>, sqlx::Error> {
    sqlx::query_as::<_, Follow>(
        "UPDATE follows SET state = $1 WHERE id = $2 RETURNING *",
    )
    .bind(state)
    .bind(follow_id)
    .fetch_optional(pool)
    .await
}

/// Delete a follow (unfollow).
pub async fn delete_follow(
    pool: &PgPool,
    follower_id: Uuid,
    following_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "DELETE FROM follows WHERE follower_id = $1 AND following_id = $2",
    )
    .bind(follower_id)
    .bind(following_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Returns all accepted followers of `user_id`.
pub async fn get_followers(pool: &PgPool, user_id: Uuid) -> Result<Vec<Follow>, sqlx::Error> {
    sqlx::query_as::<_, Follow>(
        "SELECT * FROM follows WHERE following_id = $1 AND state = 'accepted' ORDER BY created_at DESC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
}

/// Returns all accepted accounts that `user_id` follows.
pub async fn get_following(pool: &PgPool, user_id: Uuid) -> Result<Vec<Follow>, sqlx::Error> {
    sqlx::query_as::<_, Follow>(
        "SELECT * FROM follows WHERE follower_id = $1 AND state = 'accepted' ORDER BY created_at DESC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
}

/// Pending follow requests where `user_id` is the target.
pub async fn get_incoming_requests(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Vec<Follow>, sqlx::Error> {
    sqlx::query_as::<_, Follow>(
        "SELECT * FROM follows WHERE following_id = $1 AND state = 'pending' ORDER BY created_at DESC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
}

/// Look up a single follow row (any state) between two users.
pub async fn find_follow(
    pool: &PgPool,
    follower_id: Uuid,
    following_id: Uuid,
) -> Result<Option<Follow>, sqlx::Error> {
    sqlx::query_as::<_, Follow>(
        "SELECT * FROM follows WHERE follower_id = $1 AND following_id = $2",
    )
    .bind(follower_id)
    .bind(following_id)
    .fetch_optional(pool)
    .await
}

pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<Option<Follow>, sqlx::Error> {
    sqlx::query_as::<_, Follow>("SELECT * FROM follows WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
}
