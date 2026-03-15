use sqlx::PgPool;
use uuid::Uuid;

/// Upsert the read timestamp for a conversation.
/// Called when a user fetches the initial page of a conversation.
pub async fn mark_read(
    pool: &PgPool,
    user_id: Uuid,
    other_actor_uri: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO dm_conversation_reads (user_id, other_actor_uri, last_read_at)
        VALUES ($1, $2, NOW())
        ON CONFLICT (user_id, other_actor_uri)
        DO UPDATE SET last_read_at = NOW()
        "#,
    )
    .bind(user_id)
    .bind(other_actor_uri)
    .execute(pool)
    .await?;
    Ok(())
}
