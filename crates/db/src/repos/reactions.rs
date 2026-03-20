use sqlx::PgPool;
use uuid::Uuid;

use crate::models::MessageReaction;

/// Add a reaction. Uses ON CONFLICT DO UPDATE as a no-op to always return the row.
pub async fn add_reaction(
    pool: &PgPool,
    message_id: Uuid,
    reactor_actor_uri: &str,
    emoji: &str,
) -> Result<MessageReaction, sqlx::Error> {
    sqlx::query_as::<_, MessageReaction>(
        r#"
        INSERT INTO message_reactions (message_id, reactor_actor_uri, emoji)
        VALUES ($1, $2, $3)
        ON CONFLICT (message_id, reactor_actor_uri, emoji)
            DO UPDATE SET emoji = EXCLUDED.emoji
        RETURNING *
        "#,
    )
    .bind(message_id)
    .bind(reactor_actor_uri)
    .bind(emoji)
    .fetch_one(pool)
    .await
}

/// Remove a reaction. Returns true if a row was actually deleted.
pub async fn remove_reaction(
    pool: &PgPool,
    message_id: Uuid,
    reactor_actor_uri: &str,
    emoji: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        r#"
        DELETE FROM message_reactions
        WHERE message_id = $1 AND reactor_actor_uri = $2 AND emoji = $3
        "#,
    )
    .bind(message_id)
    .bind(reactor_actor_uri)
    .bind(emoji)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Grouped reaction row returned by batch queries.
#[derive(Debug, sqlx::FromRow)]
pub struct ReactionGroupRow {
    pub message_id: Uuid,
    pub emoji: String,
    pub count: i64,
    pub reacted_by_me: bool,
}

/// Batch-fetch reactions for a set of messages, grouped by (message_id, emoji).
/// Returns rows ordered by count descending within each message.
pub async fn get_reactions_for_messages(
    pool: &PgPool,
    message_ids: &[Uuid],
    viewer_actor_uri: &str,
) -> Result<Vec<ReactionGroupRow>, sqlx::Error> {
    sqlx::query_as::<_, ReactionGroupRow>(
        r#"
        SELECT
            message_id,
            emoji,
            COUNT(*)                                AS count,
            bool_or(reactor_actor_uri = $1)         AS reacted_by_me
        FROM message_reactions
        WHERE message_id = ANY($2)
        GROUP BY message_id, emoji
        ORDER BY message_id, count DESC
        "#,
    )
    .bind(viewer_actor_uri)
    .bind(message_ids)
    .fetch_all(pool)
    .await
}
