use anyhow::Context;
use domain::UserId;
use domain::e2ee::{
    ArchiveCursor, ArchiveEntry, ArchiveNonce, ArchiveSalt, ArchiveStoreError, HistoryArchive,
    NewArchiveEntry,
};
use sqlx::PgPool;
use time::OffsetDateTime;

/// `history_messages`, and `users.history_archive_salt`.
pub struct PgHistoryArchive {
    pool: PgPool,
}

impl PgHistoryArchive {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(sqlx::FromRow)]
struct EntryRow {
    id: uuid::Uuid,
    conversation_id: uuid::Uuid,
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
    client_message_id: Option<String>,
    created_at: OffsetDateTime,
}

impl TryFrom<EntryRow> for ArchiveEntry {
    type Error = anyhow::Error;

    fn try_from(row: EntryRow) -> Result<Self, Self::Error> {
        Ok(ArchiveEntry {
            id: row.id.into(),
            conversation: row.conversation_id.into(),
            ciphertext: row.ciphertext,
            nonce: ArchiveNonce::parse(&row.nonce).context("history_messages.nonce")?,
            client_message_id: row.client_message_id,
            created_at: row.created_at,
        })
    }
}

#[async_trait::async_trait]
impl HistoryArchive for PgHistoryArchive {
    async fn store(
        &self,
        owner: UserId,
        entries: &[NewArchiveEntry],
    ) -> Result<usize, ArchiveStoreError> {
        // One transaction: the upload is whole or not at all, and its entries share `now()`.
        let mut tx = self.pool.begin().await.context("begin archive upload")?;
        let mut stored = 0;
        for entry in entries {
            stored += sqlx::query(
                "INSERT INTO history_messages \
                     (id, user_id, conversation_id, ciphertext, nonce, client_message_id) \
                 VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (user_id, id) DO NOTHING",
            )
            .bind(entry.id.as_uuid())
            .bind(owner.as_uuid())
            .bind(entry.conversation.as_uuid())
            .bind(&entry.ciphertext)
            .bind(entry.nonce.as_bytes())
            .bind(entry.client_message_id.as_deref())
            .execute(&mut *tx)
            .await
            .context("archive an entry")?
            .rows_affected();
        }
        tx.commit().await.context("commit archive upload")?;
        Ok(usize::try_from(stored).unwrap_or_default())
    }

    async fn page(
        &self,
        owner: UserId,
        after: Option<ArchiveCursor>,
        limit: usize,
    ) -> Result<Vec<ArchiveEntry>, ArchiveStoreError> {
        let rows: Vec<EntryRow> = sqlx::query_as(
            "SELECT id, conversation_id, ciphertext, nonce, client_message_id, created_at \
             FROM history_messages \
             WHERE user_id = $1 AND ($2::timestamptz IS NULL OR (created_at, id) < ($2, $3)) \
             ORDER BY created_at DESC, id DESC LIMIT $4",
        )
        .bind(owner.as_uuid())
        .bind(after.map(|c| c.created_at))
        .bind(after.map(|c| c.id.as_uuid()))
        .bind(i64::try_from(limit).unwrap_or(i64::MAX))
        .fetch_all(&self.pool)
        .await
        .context("page an archive")?;
        Ok(rows
            .into_iter()
            .map(ArchiveEntry::try_from)
            .collect::<Result<_, _>>()?)
    }

    async fn clear(&self, owner: UserId) -> Result<usize, ArchiveStoreError> {
        let cleared = sqlx::query("DELETE FROM history_messages WHERE user_id = $1")
            .bind(owner.as_uuid())
            .execute(&self.pool)
            .await
            .context("clear an archive")?
            .rows_affected();
        Ok(usize::try_from(cleared).unwrap_or_default())
    }

    async fn salt(&self, owner: UserId) -> Result<Option<ArchiveSalt>, ArchiveStoreError> {
        let salt: Option<Option<Vec<u8>>> =
            sqlx::query_scalar("SELECT history_archive_salt FROM users WHERE id = $1")
                .bind(owner.as_uuid())
                .fetch_optional(&self.pool)
                .await
                .context("read an archive salt")?;
        Ok(salt
            .flatten()
            .map(|salt| ArchiveSalt::parse(&salt).context("users.history_archive_salt"))
            .transpose()?)
    }

    async fn set_salt_once(
        &self,
        owner: UserId,
        salt: &ArchiveSalt,
    ) -> Result<ArchiveSalt, ArchiveStoreError> {
        // COALESCE: two devices racing both read back the first one's salt.
        let held: Vec<u8> = sqlx::query_scalar(
            "UPDATE users SET history_archive_salt = COALESCE(history_archive_salt, $2) \
             WHERE id = $1 RETURNING history_archive_salt",
        )
        .bind(owner.as_uuid())
        .bind(salt.as_bytes())
        .fetch_one(&self.pool)
        .await
        .context("set an archive salt")?;
        Ok(ArchiveSalt::parse(&held).context("users.history_archive_salt")?)
    }
}
