use sqlx::PgPool;
use uuid::Uuid;

use crate::models::DirectMessage;

pub async fn create_message(
    pool: &PgPool,
    sender_id: Uuid,
    recipient_id: Uuid,
    content: &str,
    ap_id: Option<&str>,
) -> Result<DirectMessage, sqlx::Error> {
    sqlx::query_as::<_, DirectMessage>(
        r#"
        INSERT INTO direct_messages (sender_id, recipient_id, content, ap_id)
        VALUES ($1, $2, $3, $4)
        RETURNING *
        "#,
    )
    .bind(sender_id)
    .bind(recipient_id)
    .bind(content)
    .bind(ap_id)
    .fetch_one(pool)
    .await
}

/// Fetch the conversation between two users, oldest-first, up to `limit` messages.
pub async fn get_conversation(
    pool: &PgPool,
    user_a: Uuid,
    user_b: Uuid,
    limit: i64,
) -> Result<Vec<DirectMessage>, sqlx::Error> {
    sqlx::query_as::<_, DirectMessage>(
        r#"
        SELECT * FROM direct_messages
        WHERE (sender_id = $1 AND recipient_id = $2)
           OR (sender_id = $2 AND recipient_id = $1)
        ORDER BY created_at ASC
        LIMIT $3
        "#,
    )
    .bind(user_a)
    .bind(user_b)
    .bind(limit)
    .fetch_all(pool)
    .await
}

/// Summary row for the DM conversation list.
#[derive(Debug, sqlx::FromRow)]
pub struct ConversationSummary {
    pub other_user_id: Uuid,
    pub last_message_at: time::OffsetDateTime,
}

/// Return a list of users that `user_id` has exchanged DMs with,
/// ordered by most recent message.
pub async fn list_conversations(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Vec<ConversationSummary>, sqlx::Error> {
    sqlx::query_as::<_, ConversationSummary>(
        r#"
        SELECT
            CASE
                WHEN sender_id = $1 THEN recipient_id
                ELSE sender_id
            END AS other_user_id,
            MAX(created_at) AS last_message_at
        FROM direct_messages
        WHERE sender_id = $1 OR recipient_id = $1
        GROUP BY other_user_id
        ORDER BY last_message_at DESC
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
}
