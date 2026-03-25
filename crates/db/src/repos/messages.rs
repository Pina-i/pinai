use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::models::{DirectMessage, DirectMessageWithReply};

/// Create a new direct message in a conversation.
/// `federation_status` defaults to 'pending' in the database.
pub async fn create_message(
    pool: &PgPool,
    conversation_id: Uuid,
    sender_actor_uri: &str,
    content: &str,
    activity_uri: &str,
    reply_to_id: Option<Uuid>,
) -> Result<DirectMessage, sqlx::Error> {
    sqlx::query_as::<_, DirectMessage>(
        r#"
        INSERT INTO direct_messages (conversation_id, sender_actor_uri, content, activity_uri, reply_to_id)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING *
        "#,
    )
    .bind(conversation_id)
    .bind(sender_actor_uri)
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
    conversation_id: Uuid,
    limit: i64,
) -> Result<Vec<DirectMessageWithReply>, sqlx::Error> {
    sqlx::query_as::<_, DirectMessageWithReply>(
        r#"
        SELECT
            dm.id, dm.conversation_id, dm.sender_actor_uri, dm.content,
            dm.activity_uri, dm.federation_status, dm.created_at, dm.edited_at,
            dm.deleted_at, dm.reply_to_id,
            parent.content           AS reply_to_content,
            parent.sender_actor_uri  AS reply_to_sender
        FROM direct_messages dm
        LEFT JOIN direct_messages parent ON dm.reply_to_id = parent.id
        WHERE dm.conversation_id = $1
          AND dm.deleted_at IS NULL
        ORDER BY dm.created_at DESC, dm.id DESC
        LIMIT $2
        "#,
    )
    .bind(conversation_id)
    .bind(limit)
    .fetch_all(pool)
    .await
}

/// Fetch older messages before the given cursor `(created_at, id)` for keyset pagination,
/// with inline reply previews.
pub async fn get_conversation_before(
    pool: &PgPool,
    conversation_id: Uuid,
    cursor_created_at: OffsetDateTime,
    cursor_id: Uuid,
    limit: i64,
) -> Result<Vec<DirectMessageWithReply>, sqlx::Error> {
    sqlx::query_as::<_, DirectMessageWithReply>(
        r#"
        SELECT
            dm.id, dm.conversation_id, dm.sender_actor_uri, dm.content,
            dm.activity_uri, dm.federation_status, dm.created_at, dm.edited_at,
            dm.deleted_at, dm.reply_to_id,
            parent.content           AS reply_to_content,
            parent.sender_actor_uri  AS reply_to_sender
        FROM direct_messages dm
        LEFT JOIN direct_messages parent ON dm.reply_to_id = parent.id
        WHERE dm.conversation_id = $1
          AND dm.deleted_at IS NULL
          AND (dm.created_at, dm.id) < ($2, $3)
        ORDER BY dm.created_at DESC, dm.id DESC
        LIMIT $4
        "#,
    )
    .bind(conversation_id)
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

/// Summary row for the conversation list — returned by the enriched CTE query.
#[derive(Debug, sqlx::FromRow)]
pub struct ConversationSummary {
    pub conversation_id: Uuid,
    pub kind: String,
    pub name: Option<String>,
    pub last_message_at: Option<OffsetDateTime>,
    pub last_message_preview: Option<String>,
    pub last_message_sender: Option<String>,
    pub unread_count: i64,
    pub members: serde_json::Value,
}

/// Return the caller's conversation list with enriched data for rendering.
pub async fn list_conversations(
    pool: &PgPool,
    user_id: Uuid,
    caller_actor_uri: &str,
) -> Result<Vec<ConversationSummary>, sqlx::Error> {
    sqlx::query_as::<_, ConversationSummary>(
        r#"
        WITH ranked_messages AS (
            SELECT
                dm.conversation_id,
                dm.sender_actor_uri,
                dm.content,
                dm.created_at,
                ROW_NUMBER() OVER (
                    PARTITION BY dm.conversation_id
                    ORDER BY dm.created_at DESC, dm.id DESC
                ) AS rn
            FROM direct_messages dm
            WHERE dm.deleted_at IS NULL
        )
        SELECT
            c.id                                        AS conversation_id,
            c.kind,
            c.name,
            MAX(rm.created_at)                          AS last_message_at,
            (SELECT LEFT(rm2.content, 100)
             FROM ranked_messages rm2
             WHERE rm2.conversation_id = c.id AND rm2.rn = 1)
                                                        AS last_message_preview,
            (SELECT rm2.sender_actor_uri
             FROM ranked_messages rm2
             WHERE rm2.conversation_id = c.id AND rm2.rn = 1)
                                                        AS last_message_sender,
            COUNT(CASE
                WHEN rm.sender_actor_uri != $1
                     AND (r.last_read_at IS NULL OR rm.created_at > r.last_read_at)
                THEN 1 ELSE NULL
            END)                                        AS unread_count,
            COALESCE(
                (SELECT JSON_AGG(
                    JSON_BUILD_OBJECT(
                        'actorUri',    cm_other.actor_uri,
                        'displayName', COALESCE(u.display_name, ra.display_name)
                    )
                )
                FROM conversation_members cm_other
                LEFT JOIN users u
                    ON u.actor_uri = cm_other.actor_uri
                LEFT JOIN remote_actors ra
                    ON ra.actor_uri = cm_other.actor_uri
                WHERE cm_other.conversation_id = c.id
                  AND cm_other.left_at IS NULL
                  AND cm_other.actor_uri != $1),
                '[]'
            )                                           AS members
        FROM conversation_members cm_self
        JOIN conversations c
            ON c.id = cm_self.conversation_id
        LEFT JOIN ranked_messages rm
            ON rm.conversation_id = c.id
        LEFT JOIN conversation_reads r
            ON r.user_id = $2 AND r.conversation_id = c.id
        WHERE cm_self.actor_uri = $1
          AND cm_self.left_at IS NULL
        GROUP BY c.id, c.kind, c.name, cm_self.conversation_id
        ORDER BY last_message_at DESC NULLS LAST
        "#,
    )
    .bind(caller_actor_uri)
    .bind(user_id)
    .fetch_all(pool)
    .await
}
