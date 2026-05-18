//! Server-opaque archive of plaintext encrypted under the History Archive Key.
//! PK `(user_id, id)` — first decryptor wins; subsequent uploads from the
//! user's other devices no-op via `ON CONFLICT DO NOTHING`.

use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct HistoryMessage {
    pub id: Uuid,
    pub user_id: Uuid,
    pub conversation_id: Uuid,
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub client_message_id: Option<String>,
    pub created_at: OffsetDateTime,
}

pub struct InsertEntry<'a> {
    pub id: Uuid,
    pub conversation_id: Uuid,
    pub ciphertext: &'a [u8],
    pub nonce: &'a [u8],
    pub client_message_id: Option<&'a str>,
}

/// Idempotent batch upsert keyed on `(user_id, id)`.
pub async fn insert_batch(
    pool: &PgPool,
    user_id: Uuid,
    entries: &[InsertEntry<'_>],
) -> Result<usize, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let mut inserted = 0usize;
    for e in entries {
        let result = sqlx::query(
            r#"
            INSERT INTO history_messages
                (id, user_id, conversation_id, ciphertext, nonce, client_message_id)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (user_id, id) DO NOTHING
            "#,
        )
        .bind(e.id)
        .bind(user_id)
        .bind(e.conversation_id)
        .bind(e.ciphertext)
        .bind(e.nonce)
        .bind(e.client_message_id)
        .execute(&mut *tx)
        .await?;
        inserted += result.rows_affected() as usize;
    }
    tx.commit().await?;
    Ok(inserted)
}

/// Keyset pagination over `(created_at DESC, id DESC)`.
pub async fn page(
    pool: &PgPool,
    user_id: Uuid,
    after: Option<(OffsetDateTime, Uuid)>,
    limit: i64,
) -> Result<Vec<HistoryMessage>, sqlx::Error> {
    match after {
        None => sqlx::query_as::<_, HistoryMessage>(
            r#"
            SELECT id, user_id, conversation_id, ciphertext, nonce,
                   client_message_id, created_at
            FROM history_messages
            WHERE user_id = $1
            ORDER BY created_at DESC, id DESC
            LIMIT $2
            "#,
        )
        .bind(user_id)
        .bind(limit)
        .fetch_all(pool)
        .await,
        Some((ts, id)) => sqlx::query_as::<_, HistoryMessage>(
            r#"
            SELECT id, user_id, conversation_id, ciphertext, nonce,
                   client_message_id, created_at
            FROM history_messages
            WHERE user_id = $1
              AND (created_at, id) < ($2, $3)
            ORDER BY created_at DESC, id DESC
            LIMIT $4
            "#,
        )
        .bind(user_id)
        .bind(ts)
        .bind(id)
        .bind(limit)
        .fetch_all(pool)
        .await,
    }
}

pub async fn delete_all(pool: &PgPool, user_id: Uuid) -> Result<u64, sqlx::Error> {
    let r = sqlx::query("DELETE FROM history_messages WHERE user_id = $1")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(r.rows_affected())
}
