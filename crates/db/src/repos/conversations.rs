use sqlx::PgPool;
use uuid::Uuid;

use crate::models::{Conversation, ConversationMember};

/// Create a new conversation with the given kind and optional name.
pub async fn create_conversation(
    pool: &PgPool,
    kind: &str,
    name: Option<&str>,
) -> Result<Conversation, sqlx::Error> {
    sqlx::query_as::<_, Conversation>(
        r#"
        INSERT INTO conversations (kind, name)
        VALUES ($1, $2)
        RETURNING *
        "#,
    )
    .bind(kind)
    .bind(name)
    .fetch_one(pool)
    .await
}

/// Create a conversation with a specific UUID (used for federation).
pub async fn create_conversation_with_id(
    pool: &PgPool,
    id: Uuid,
    kind: &str,
    name: Option<&str>,
) -> Result<Conversation, sqlx::Error> {
    sqlx::query_as::<_, Conversation>(
        r#"
        INSERT INTO conversations (id, kind, name)
        VALUES ($1, $2, $3)
        RETURNING *
        "#,
    )
    .bind(id)
    .bind(kind)
    .bind(name)
    .fetch_one(pool)
    .await
}

/// Find a conversation by its ID.
pub async fn find_by_id(
    pool: &PgPool,
    id: Uuid,
) -> Result<Option<Conversation>, sqlx::Error> {
    sqlx::query_as::<_, Conversation>(
        "SELECT * FROM conversations WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
}

/// Add a member to a conversation.
pub async fn add_member(
    pool: &PgPool,
    conversation_id: Uuid,
    actor_uri: &str,
) -> Result<ConversationMember, sqlx::Error> {
    sqlx::query_as::<_, ConversationMember>(
        r#"
        INSERT INTO conversation_members (conversation_id, actor_uri)
        VALUES ($1, $2)
        ON CONFLICT (conversation_id, actor_uri)
            DO UPDATE SET left_at = NULL
        RETURNING *
        "#,
    )
    .bind(conversation_id)
    .bind(actor_uri)
    .fetch_one(pool)
    .await
}

/// Find the existing DM conversation between exactly two actors.
/// Returns the conversation ID if one exists.
pub async fn find_dm_between(
    pool: &PgPool,
    actor_a: &str,
    actor_b: &str,
) -> Result<Option<Uuid>, sqlx::Error> {
    let row = sqlx::query_scalar::<_, Uuid>(
        r#"
        SELECT cm1.conversation_id
        FROM conversation_members cm1
        JOIN conversation_members cm2
            ON cm2.conversation_id = cm1.conversation_id
           AND cm2.actor_uri = $2
           AND cm2.left_at IS NULL
        JOIN conversations c
            ON c.id = cm1.conversation_id
           AND c.kind = 'dm'
        WHERE cm1.actor_uri = $1
          AND cm1.left_at IS NULL
        LIMIT 1
        "#,
    )
    .bind(actor_a)
    .bind(actor_b)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Find or create a DM conversation between two actors.
/// Returns (conversation_id, created) where `created` indicates whether a new
/// conversation was created.
pub async fn get_or_create_dm(
    pool: &PgPool,
    actor_a: &str,
    actor_b: &str,
) -> Result<(Uuid, bool), sqlx::Error> {
    if let Some(conv_id) = find_dm_between(pool, actor_a, actor_b).await? {
        return Ok((conv_id, false));
    }

    let conv = create_conversation(pool, "dm", None).await?;
    add_member(pool, conv.id, actor_a).await?;
    add_member(pool, conv.id, actor_b).await?;
    Ok((conv.id, true))
}

/// Find or create a DM conversation using a specific UUID (federation).
pub async fn get_or_create_dm_with_id(
    pool: &PgPool,
    id: Uuid,
    actor_a: &str,
    actor_b: &str,
) -> Result<(Uuid, bool), sqlx::Error> {
    if let Some(conv_id) = find_dm_between(pool, actor_a, actor_b).await? {
        return Ok((conv_id, false));
    }

    // Check if this specific UUID already exists (another instance created it)
    if let Some(_) = find_by_id(pool, id).await? {
        return Ok((id, false));
    }

    let conv = create_conversation_with_id(pool, id, "dm", None).await?;
    add_member(pool, conv.id, actor_a).await?;
    add_member(pool, conv.id, actor_b).await?;
    Ok((conv.id, true))
}

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

/// Get the actor_uri of the other member in a DM conversation.
pub async fn get_dm_other_member(
    pool: &PgPool,
    conversation_id: Uuid,
    caller_actor_uri: &str,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar::<_, String>(
        r#"
        SELECT actor_uri FROM conversation_members
        WHERE conversation_id = $1
          AND actor_uri != $2
          AND left_at IS NULL
        LIMIT 1
        "#,
    )
    .bind(conversation_id)
    .bind(caller_actor_uri)
    .fetch_optional(pool)
    .await
}

/// Update the name of a group conversation.
pub async fn update_name(
    pool: &PgPool,
    conversation_id: Uuid,
    name: &str,
) -> Result<Option<Conversation>, sqlx::Error> {
    sqlx::query_as::<_, Conversation>(
        r#"
        UPDATE conversations
        SET name = $2
        WHERE id = $1 AND kind = 'group'
        RETURNING *
        "#,
    )
    .bind(conversation_id)
    .bind(name)
    .fetch_optional(pool)
    .await
}

/// Member info row for conversation list display names.
#[derive(Debug, sqlx::FromRow)]
pub struct MemberActorUri {
    pub actor_uri: String,
}

/// Get all active member actor_uris for a conversation, excluding the caller.
pub async fn get_other_member_uris(
    pool: &PgPool,
    conversation_id: Uuid,
    exclude_actor_uri: &str,
) -> Result<Vec<String>, sqlx::Error> {
    let rows = sqlx::query_scalar::<_, String>(
        r#"
        SELECT actor_uri FROM conversation_members
        WHERE conversation_id = $1
          AND actor_uri != $2
          AND left_at IS NULL
        "#,
    )
    .bind(conversation_id)
    .bind(exclude_actor_uri)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}
