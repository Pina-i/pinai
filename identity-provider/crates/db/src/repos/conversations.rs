use sqlx::PgPool;
use uuid::Uuid;

use crate::models::ConversationMember;

/// Get active members of a conversation (excluding those who left).
pub async fn get_members(
    pool: &PgPool,
    conversation_id: Uuid,
) -> Result<Vec<ConversationMember>, sqlx::Error> {
    sqlx::query_as::<_, ConversationMember>(
        r#"
        SELECT * FROM conversation_members
        WHERE conversation_id = $1 AND left_at IS NULL
        "#,
    )
    .bind(conversation_id)
    .fetch_all(pool)
    .await
}

/// Find all conversation IDs where the given actor is an active member.
pub async fn find_conversations_for_actor(
    pool: &PgPool,
    actor_uri: &str,
) -> Result<Vec<Uuid>, sqlx::Error> {
    sqlx::query_scalar::<_, Uuid>(
        r#"
        SELECT conversation_id FROM conversation_members
        WHERE actor_uri = $1
          AND left_at IS NULL
        "#,
    )
    .bind(actor_uri)
    .fetch_all(pool)
    .await
}
