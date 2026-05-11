//! Repository for `mls_welcomes` — outbound queue for offline device adds.
//!
//! When a member of a group adds a new device (or a new user), the proposing
//! device builds a Welcome bundle and POSTs it to the recipient's IdP. The DS
//! stores it here until the targeted device fetches it; then `consumed_at`
//! is stamped so the same bundle isn't handed out twice.
//!
//! Pending rows are eventually GC'd by the orphan-sweep on a `consumed_at`
//! grace window (same pattern as `key_packages`).

use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct MlsWelcome {
    pub id: Uuid,
    pub recipient_user_id: Uuid,
    pub recipient_device_id: Uuid,
    pub conversation_id: Uuid,
    pub welcome_blob: Vec<u8>,
    pub created_at: OffsetDateTime,
    pub consumed_at: Option<OffsetDateTime>,
}

/// Persist a Welcome bundle for a target device. Called either from the
/// REST send path (local recipient) or from the AP inbox handler when a peer
/// IdP delivers a federated Welcome.
pub async fn insert_welcome(
    pool: &PgPool,
    recipient_user_id: Uuid,
    recipient_device_id: Uuid,
    conversation_id: Uuid,
    welcome_blob: &[u8],
) -> Result<MlsWelcome, sqlx::Error> {
    sqlx::query_as::<_, MlsWelcome>(
        r#"
        INSERT INTO mls_welcomes
            (recipient_user_id, recipient_device_id, conversation_id, welcome_blob)
        VALUES ($1, $2, $3, $4)
        RETURNING *
        "#,
    )
    .bind(recipient_user_id)
    .bind(recipient_device_id)
    .bind(conversation_id)
    .bind(welcome_blob)
    .fetch_one(pool)
    .await
}

/// Atomically fetch and consume every pending Welcome targeted at the given
/// `(user_id, device_id)` pair.
///
/// Per-device rather than per-user: each Welcome is bound to a specific leaf,
/// so a multi-device user must pull only the bundles meant for the calling
/// device. A user-level claim would race — the first device to call wins all
/// rows, leaving siblings empty-handed for their own welcomes.
///
/// `UPDATE … RETURNING *` runs in a single round-trip and is race-safe under
/// concurrent fetches: a Welcome can only ever transition `NULL → now()`,
/// and `FOR UPDATE SKIP LOCKED` ensures concurrent claims can't double-read
/// the same row.
pub async fn claim_pending_for_device(
    pool: &PgPool,
    recipient_user_id: Uuid,
    recipient_device_id: Uuid,
) -> Result<Vec<MlsWelcome>, sqlx::Error> {
    sqlx::query_as::<_, MlsWelcome>(
        r#"
        UPDATE mls_welcomes
        SET consumed_at = now()
        WHERE id IN (
            SELECT id FROM mls_welcomes
            WHERE recipient_user_id = $1
              AND recipient_device_id = $2
              AND consumed_at IS NULL
            FOR UPDATE SKIP LOCKED
        )
        RETURNING *
        "#,
    )
    .bind(recipient_user_id)
    .bind(recipient_device_id)
    .fetch_all(pool)
    .await
}

/// Garbage-collect rows that have been consumed for over a day. Called from
/// the existing orphan-sweep background task. We keep them around briefly
/// after consume so a client retrying a fetch (e.g. socket dropped while
/// reading) sees a clean empty result rather than re-receiving the bundle.
pub async fn delete_old(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        r#"
        DELETE FROM mls_welcomes
        WHERE consumed_at < now() - interval '1 day'
        "#,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}
