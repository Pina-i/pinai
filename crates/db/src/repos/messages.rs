use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::models::DirectMessage;

/// Create a new direct message using actor URIs.
/// `federation_status` defaults to 'pending' in the database.
pub async fn create_message(
    pool: &PgPool,
    sender_actor_uri: &str,
    recipient_actor_uri: &str,
    content: &str,
    activity_uri: &str,
) -> Result<DirectMessage, sqlx::Error> {
    sqlx::query_as::<_, DirectMessage>(
        r#"
        INSERT INTO direct_messages (sender_actor_uri, recipient_actor_uri, content, activity_uri)
        VALUES ($1, $2, $3, $4)
        RETURNING *
        "#,
    )
    .bind(sender_actor_uri)
    .bind(recipient_actor_uri)
    .bind(content)
    .bind(activity_uri)
    .fetch_one(pool)
    .await
}

/// Fetch the initial page of a conversation (most recent 50 messages, newest first).
/// Only returns non-deleted messages.
pub async fn get_conversation(
    pool: &PgPool,
    actor_a: &str,
    actor_b: &str,
    limit: i64,
) -> Result<Vec<DirectMessage>, sqlx::Error> {
    sqlx::query_as::<_, DirectMessage>(
        r#"
        SELECT * FROM direct_messages
        WHERE ((sender_actor_uri = $1 AND recipient_actor_uri = $2)
           OR  (sender_actor_uri = $2 AND recipient_actor_uri = $1))
          AND deleted_at IS NULL
        ORDER BY created_at DESC, id DESC
        LIMIT $3
        "#,
    )
    .bind(actor_a)
    .bind(actor_b)
    .bind(limit)
    .fetch_all(pool)
    .await
}

/// Fetch older messages before the given cursor `(created_at, id)` for keyset pagination.
/// Returns messages in newest-first order within the page.
pub async fn get_conversation_before(
    pool: &PgPool,
    actor_a: &str,
    actor_b: &str,
    cursor_created_at: OffsetDateTime,
    cursor_id: Uuid,
    limit: i64,
) -> Result<Vec<DirectMessage>, sqlx::Error> {
    sqlx::query_as::<_, DirectMessage>(
        r#"
        SELECT * FROM direct_messages
        WHERE ((sender_actor_uri = $1 AND recipient_actor_uri = $2)
           OR  (sender_actor_uri = $2 AND recipient_actor_uri = $1))
          AND deleted_at IS NULL
          AND (created_at, id) < ($3, $4)
        ORDER BY created_at DESC, id DESC
        LIMIT $5
        "#,
    )
    .bind(actor_a)
    .bind(actor_b)
    .bind(cursor_created_at)
    .bind(cursor_id)
    .bind(limit)
    .fetch_all(pool)
    .await
}

/// Update the federation status of a message by its activity_uri.
pub async fn update_federation_status(
    pool: &PgPool,
    activity_uri: &str,
    status: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE direct_messages
        SET federation_status = $2
        WHERE activity_uri = $1
        "#,
    )
    .bind(activity_uri)
    .bind(status)
    .execute(pool)
    .await?;
    Ok(())
}

/// Summary row for the DM conversation list.
#[derive(Debug, sqlx::FromRow)]
pub struct ConversationSummary {
    pub other_actor_uri: String,
    pub last_message_at: OffsetDateTime,
}

/// Return a list of actors that `actor_uri` has exchanged DMs with,
/// ordered by most recent message.
pub async fn list_conversations(
    pool: &PgPool,
    actor_uri: &str,
) -> Result<Vec<ConversationSummary>, sqlx::Error> {
    sqlx::query_as::<_, ConversationSummary>(
        r#"
        SELECT
            CASE
                WHEN sender_actor_uri = $1 THEN recipient_actor_uri
                ELSE sender_actor_uri
            END AS other_actor_uri,
            MAX(created_at) AS last_message_at
        FROM direct_messages
        WHERE (sender_actor_uri = $1 OR recipient_actor_uri = $1)
          AND deleted_at IS NULL
        GROUP BY other_actor_uri
        ORDER BY last_message_at DESC
        "#,
    )
    .bind(actor_uri)
    .fetch_all(pool)
    .await
}
