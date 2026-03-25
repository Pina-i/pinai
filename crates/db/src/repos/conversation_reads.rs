use sqlx::PgPool;
use uuid::Uuid;

/// Upsert the read timestamp for a conversation.
/// Called when a user fetches the initial page of a conversation.
pub async fn mark_read(
    pool: &PgPool,
    user_id: Uuid,
    conversation_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO conversation_reads (user_id, conversation_id, last_read_at)
        VALUES ($1, $2, NOW())
        ON CONFLICT (user_id, conversation_id)
        DO UPDATE SET last_read_at = NOW()
        "#,
    )
    .bind(user_id)
    .bind(conversation_id)
    .execute(pool)
    .await?;
    Ok(())
}
