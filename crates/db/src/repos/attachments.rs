use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::models::Attachment;

/// Insert an orphan attachment (message_id = NULL). The caller uploads the
/// bytes to RustFS keyed by `storage_key` (typically `id.to_string()`).
pub async fn insert_orphan(
    pool: &PgPool,
    id: Uuid,
    uploaded_by_actor_uri: &str,
    storage_key: &str,
    mime_type: &str,
    byte_size: i64,
    original_filename: &str,
) -> Result<Attachment, sqlx::Error> {
    sqlx::query_as::<_, Attachment>(
        r#"
        INSERT INTO message_attachments
            (id, uploaded_by_actor_uri, storage_key, mime_type, byte_size, original_filename)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING *
        "#,
    )
    .bind(id)
    .bind(uploaded_by_actor_uri)
    .bind(storage_key)
    .bind(mime_type)
    .bind(byte_size)
    .bind(original_filename)
    .fetch_one(pool)
    .await
}

/// Insert a remote attachment (received via federation inbox). `message_id` is
/// known immediately and `remote_origin_url` is set; bytes live on the origin IdP.
pub async fn insert_remote(
    pool: &PgPool,
    id: Uuid,
    message_id: Uuid,
    uploaded_by_actor_uri: &str,
    storage_key: &str,
    mime_type: &str,
    byte_size: i64,
    original_filename: &str,
    remote_origin_url: &str,
) -> Result<Attachment, sqlx::Error> {
    sqlx::query_as::<_, Attachment>(
        r#"
        INSERT INTO message_attachments
            (id, message_id, uploaded_by_actor_uri, storage_key, mime_type, byte_size,
             original_filename, remote_origin_url)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING *
        "#,
    )
    .bind(id)
    .bind(message_id)
    .bind(uploaded_by_actor_uri)
    .bind(storage_key)
    .bind(mime_type)
    .bind(byte_size)
    .bind(original_filename)
    .bind(remote_origin_url)
    .fetch_one(pool)
    .await
}

/// Atomically link a list of orphan attachments to a freshly-created message.
///
/// Updates only rows that (a) match an ID in `attachment_ids`, (b) are still
/// orphan (`message_id IS NULL`), and (c) are owned by `uploader_actor_uri`.
/// The third condition prevents a sender from claiming someone else's orphan.
///
/// Returns the number of rows actually linked. Callers should compare against
/// `attachment_ids.len()` and treat a mismatch as an integrity error.
pub async fn link_to_message(
    pool: &PgPool,
    attachment_ids: &[Uuid],
    message_id: Uuid,
    uploader_actor_uri: &str,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        r#"
        UPDATE message_attachments
        SET message_id = $1
        WHERE id = ANY($2)
          AND message_id IS NULL
          AND uploaded_by_actor_uri = $3
        "#,
    )
    .bind(message_id)
    .bind(attachment_ids)
    .bind(uploader_actor_uri)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<Option<Attachment>, sqlx::Error> {
    sqlx::query_as::<_, Attachment>("SELECT * FROM message_attachments WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
}

/// Fetch the rows matching `(ids, owner)` that are still orphan. Used by
/// `send_message` as a precheck — the caller compares the returned length
/// against the input length to detect missing/owned-by-someone-else/already-linked
/// attachments before creating a message it'd then have to clean up.
pub async fn find_orphans_owned_by(
    pool: &PgPool,
    ids: &[Uuid],
    owner_actor_uri: &str,
) -> Result<Vec<Attachment>, sqlx::Error> {
    sqlx::query_as::<_, Attachment>(
        r#"
        SELECT * FROM message_attachments
        WHERE id = ANY($1)
          AND message_id IS NULL
          AND uploaded_by_actor_uri = $2
        "#,
    )
    .bind(ids)
    .bind(owner_actor_uri)
    .fetch_all(pool)
    .await
}

/// All attachments linked to a single message, oldest first.
pub async fn find_for_message(
    pool: &PgPool,
    message_id: Uuid,
) -> Result<Vec<Attachment>, sqlx::Error> {
    sqlx::query_as::<_, Attachment>(
        r#"
        SELECT * FROM message_attachments
        WHERE message_id = $1
        ORDER BY created_at ASC
        "#,
    )
    .bind(message_id)
    .fetch_all(pool)
    .await
}

/// Batch-fetch attachments for a set of message IDs (used by `GET /api/dm/{conv_id}`
/// to enrich a page of messages without an N+1 query).
pub async fn find_for_messages(
    pool: &PgPool,
    message_ids: &[Uuid],
) -> Result<Vec<Attachment>, sqlx::Error> {
    sqlx::query_as::<_, Attachment>(
        r#"
        SELECT * FROM message_attachments
        WHERE message_id = ANY($1)
        ORDER BY message_id, created_at ASC
        "#,
    )
    .bind(message_ids)
    .fetch_all(pool)
    .await
}

/// Orphans older than `cutoff`. Used by the orphan-sweep background task.
pub async fn find_orphans_older_than(
    pool: &PgPool,
    cutoff: OffsetDateTime,
) -> Result<Vec<Attachment>, sqlx::Error> {
    sqlx::query_as::<_, Attachment>(
        r#"
        SELECT * FROM message_attachments
        WHERE message_id IS NULL AND created_at < $1
        "#,
    )
    .bind(cutoff)
    .fetch_all(pool)
    .await
}

/// Hard-delete by ID. Returns true if a row was actually removed.
pub async fn delete_by_id(pool: &PgPool, id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM message_attachments WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}
