use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::models::{DirectMessage, DirectMessageWithReply};

/// Create a new direct message using actor URIs.
/// `federation_status` defaults to 'pending' in the database.
pub async fn create_message(
    pool: &PgPool,
    sender_actor_uri: &str,
    recipient_actor_uri: &str,
    content: &str,
    activity_uri: &str,
    reply_to_id: Option<Uuid>,
) -> Result<DirectMessage, sqlx::Error> {
    sqlx::query_as::<_, DirectMessage>(
        r#"
        INSERT INTO direct_messages (sender_actor_uri, recipient_actor_uri, content, activity_uri, reply_to_id)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING *
        "#,
    )
    .bind(sender_actor_uri)
    .bind(recipient_actor_uri)
    .bind(content)
    .bind(activity_uri)
    .bind(reply_to_id)
    .fetch_one(pool)
    .await
}

/// Find a message by its primary key.
pub async fn find_by_id(
    pool: &PgPool,
    id: Uuid,
) -> Result<Option<DirectMessage>, sqlx::Error> {
    sqlx::query_as::<_, DirectMessage>(
        "SELECT * FROM direct_messages WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
}

/// Find a message by its ActivityPub activity URI.
pub async fn find_by_activity_uri(
    pool: &PgPool,
    activity_uri: &str,
) -> Result<Option<DirectMessage>, sqlx::Error> {
    sqlx::query_as::<_, DirectMessage>(
        "SELECT * FROM direct_messages WHERE activity_uri = $1",
    )
    .bind(activity_uri)
    .fetch_optional(pool)
    .await
}

/// Fetch the initial page of a conversation (most recent messages, newest first)
/// with inline reply previews via LEFT JOIN on the parent message.
pub async fn get_conversation(
    pool: &PgPool,
    actor_a: &str,
    actor_b: &str,
    limit: i64,
) -> Result<Vec<DirectMessageWithReply>, sqlx::Error> {
    sqlx::query_as::<_, DirectMessageWithReply>(
        r#"
        SELECT
            dm.id, dm.sender_actor_uri, dm.recipient_actor_uri, dm.content,
            dm.activity_uri, dm.federation_status, dm.created_at, dm.edited_at,
            dm.deleted_at, dm.reply_to_id,
            parent.content           AS reply_to_content,
            parent.sender_actor_uri  AS reply_to_sender
        FROM direct_messages dm
        LEFT JOIN direct_messages parent ON dm.reply_to_id = parent.id
        WHERE ((dm.sender_actor_uri = $1 AND dm.recipient_actor_uri = $2)
           OR  (dm.sender_actor_uri = $2 AND dm.recipient_actor_uri = $1))
          AND dm.deleted_at IS NULL
        ORDER BY dm.created_at DESC, dm.id DESC
        LIMIT $3
        "#,
    )
    .bind(actor_a)
    .bind(actor_b)
    .bind(limit)
    .fetch_all(pool)
    .await
}

/// Fetch older messages before the given cursor `(created_at, id)` for keyset pagination,
/// with inline reply previews.
pub async fn get_conversation_before(
    pool: &PgPool,
    actor_a: &str,
    actor_b: &str,
    cursor_created_at: OffsetDateTime,
    cursor_id: Uuid,
    limit: i64,
) -> Result<Vec<DirectMessageWithReply>, sqlx::Error> {
    sqlx::query_as::<_, DirectMessageWithReply>(
        r#"
        SELECT
            dm.id, dm.sender_actor_uri, dm.recipient_actor_uri, dm.content,
            dm.activity_uri, dm.federation_status, dm.created_at, dm.edited_at,
            dm.deleted_at, dm.reply_to_id,
            parent.content           AS reply_to_content,
            parent.sender_actor_uri  AS reply_to_sender
        FROM direct_messages dm
        LEFT JOIN direct_messages parent ON dm.reply_to_id = parent.id
        WHERE ((dm.sender_actor_uri = $1 AND dm.recipient_actor_uri = $2)
           OR  (dm.sender_actor_uri = $2 AND dm.recipient_actor_uri = $1))
          AND dm.deleted_at IS NULL
          AND (dm.created_at, dm.id) < ($3, $4)
        ORDER BY dm.created_at DESC, dm.id DESC
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

/// Edit the content of a message. Only the original sender can edit.
/// Returns the updated message, or `None` if not found / caller is not the sender.
pub async fn edit_message(
    pool: &PgPool,
    id: Uuid,
    sender_actor_uri: &str,
    new_content: &str,
) -> Result<Option<DirectMessage>, sqlx::Error> {
    sqlx::query_as::<_, DirectMessage>(
        r#"
        UPDATE direct_messages
        SET content = $3, edited_at = now()
        WHERE id = $1
          AND sender_actor_uri = $2
          AND deleted_at IS NULL
        RETURNING *
        "#,
    )
    .bind(id)
    .bind(sender_actor_uri)
    .bind(new_content)
    .fetch_optional(pool)
    .await
}

/// Update the content of a message matched by activity_uri (used for federated edits).
/// Returns whether a row was updated.
pub async fn edit_message_by_activity_uri(
    pool: &PgPool,
    activity_uri: &str,
    sender_actor_uri: &str,
    new_content: &str,
) -> Result<Option<DirectMessage>, sqlx::Error> {
    sqlx::query_as::<_, DirectMessage>(
        r#"
        UPDATE direct_messages
        SET content = $3, edited_at = now()
        WHERE activity_uri = $1
          AND sender_actor_uri = $2
          AND deleted_at IS NULL
        RETURNING *
        "#,
    )
    .bind(activity_uri)
    .bind(sender_actor_uri)
    .bind(new_content)
    .fetch_optional(pool)
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
    /// Messages received from this actor since the user last read the conversation.
    pub unread_count: i64,
}

/// Return a list of actors that `actor_uri` has exchanged DMs with,
/// ordered by most recent message, with per-conversation unread counts.
pub async fn list_conversations(
    pool: &PgPool,
    user_id: Uuid,
    caller_actor_uri: &str,
) -> Result<Vec<ConversationSummary>, sqlx::Error> {
    sqlx::query_as::<_, ConversationSummary>(
        r#"
        WITH convos AS (
            SELECT
                CASE
                    WHEN dm.sender_actor_uri = $1 THEN dm.recipient_actor_uri
                    ELSE dm.sender_actor_uri
                END AS other_actor_uri,
                dm.recipient_actor_uri,
                dm.created_at
            FROM direct_messages dm
            WHERE (dm.sender_actor_uri = $1 OR dm.recipient_actor_uri = $1)
              AND dm.deleted_at IS NULL
        )
        SELECT
            c.other_actor_uri,
            MAX(c.created_at) AS last_message_at,
            COUNT(CASE
                WHEN c.recipient_actor_uri = $1
                     AND (r.last_read_at IS NULL OR c.created_at > r.last_read_at)
                THEN 1
                ELSE NULL
            END) AS unread_count
        FROM convos c
        LEFT JOIN dm_conversation_reads r
            ON r.user_id = $2 AND r.other_actor_uri = c.other_actor_uri
        GROUP BY c.other_actor_uri
        ORDER BY last_message_at DESC
        "#,
    )
    .bind(caller_actor_uri)
    .bind(user_id)
    .fetch_all(pool)
    .await
}
