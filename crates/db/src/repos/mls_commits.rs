//! Repository for `mls_commits` — per-conversation MLS commit log.
//!
//! The body is opaque to the server. Each row is a TLS-encoded MLS Commit
//! message; the IdP just orders and serves them. Total order per group is
//! enforced by the `UNIQUE(conversation_id, epoch)` constraint — concurrent
//! commits at the same epoch produce a unique-violation error that the
//! handler turns into `409 Conflict` with the winning row attached.

use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct MlsCommit {
    pub id: Uuid,
    pub conversation_id: Uuid,
    pub epoch: i64,
    pub commit_blob: Vec<u8>,
    pub proposer_actor_uri: String,
    pub created_at: OffsetDateTime,
}

/// Outcome of `insert_commit`. `Conflict` carries the row that won the race so
/// the loser's client can apply it locally and re-propose.
pub enum InsertOutcome {
    Inserted(MlsCommit),
    Conflict(MlsCommit),
}

/// Append a commit at the given `epoch`, racing against other concurrent
/// proposers. The winning insert is the first one to land; everything else
/// gets the winning row back as a conflict.
///
/// The fetch-back of the winning row tolerates the rare case where the
/// conflicting row gets deleted between INSERT and SELECT (only path is the
/// owning conversation being deleted, which would have made our own attempt
/// fail too).
pub async fn insert_commit(
    pool: &PgPool,
    conversation_id: Uuid,
    epoch: i64,
    commit_blob: &[u8],
    proposer_actor_uri: &str,
) -> Result<InsertOutcome, sqlx::Error> {
    let result = sqlx::query_as::<_, MlsCommit>(
        r#"
        INSERT INTO mls_commits (conversation_id, epoch, commit_blob, proposer_actor_uri)
        VALUES ($1, $2, $3, $4)
        RETURNING *
        "#,
    )
    .bind(conversation_id)
    .bind(epoch)
    .bind(commit_blob)
    .bind(proposer_actor_uri)
    .fetch_one(pool)
    .await;

    match result {
        Ok(row) => Ok(InsertOutcome::Inserted(row)),
        Err(sqlx::Error::Database(db_err)) if db_err.is_unique_violation() => {
            // Someone else won this epoch — fetch what they wrote and return it
            // as the conflict body.
            let winner = find_by_epoch(pool, conversation_id, epoch)
                .await?
                .ok_or_else(|| {
                    sqlx::Error::Protocol(
                        "unique violation but no winning row found".to_string(),
                    )
                })?;
            Ok(InsertOutcome::Conflict(winner))
        }
        Err(e) => Err(e),
    }
}

/// Fetch the single commit row at a specific `(conversation, epoch)`.
pub async fn find_by_epoch(
    pool: &PgPool,
    conversation_id: Uuid,
    epoch: i64,
) -> Result<Option<MlsCommit>, sqlx::Error> {
    sqlx::query_as::<_, MlsCommit>(
        r#"
        SELECT * FROM mls_commits
        WHERE conversation_id = $1 AND epoch = $2
        "#,
    )
    .bind(conversation_id)
    .bind(epoch)
    .fetch_optional(pool)
    .await
}

/// Catch-up query for clients reconnecting or syncing a new device. Returns
/// every commit `> since` in epoch order.
///
/// `limit` caps the result set so a stale client trying to pull years of
/// history can't OOM the server. The handler exposes the tail of this — when
/// the client gets `limit` rows back it should re-call with the new max
/// epoch.
pub async fn list_since(
    pool: &PgPool,
    conversation_id: Uuid,
    since_epoch: i64,
    limit: i64,
) -> Result<Vec<MlsCommit>, sqlx::Error> {
    sqlx::query_as::<_, MlsCommit>(
        r#"
        SELECT * FROM mls_commits
        WHERE conversation_id = $1 AND epoch > $2
        ORDER BY epoch ASC
        LIMIT $3
        "#,
    )
    .bind(conversation_id)
    .bind(since_epoch)
    .bind(limit)
    .fetch_all(pool)
    .await
}
