use anyhow::Context;
use domain::e2ee::{
    ApprovalPublicKey, ArchiveCursor, ArchiveEntry, ArchiveError, ArchiveNonce, ArchiveStoreError,
    Archived, HeldHistoryKey, HistoryArchive, HistoryCheckValue, HistoryGeneration, HistoryKey,
    HistoryKeys, HistorySalt, KeyGate, KeyReplace, NewArchiveEntry, check_history_generation,
    may_replace_history_key,
};
use domain::{DeviceId, UserId};
use sqlx::{PgConnection, PgPool};
use time::OffsetDateTime;

use super::approval::{drop_older_passphrase_approvals, trust_facts};
use super::auth::sessions_of;
use super::key_share::delete_shares_of;
use super::start_over::{end_with_generation, locked_open};

/// `history_messages`, written under the generation `history_keys` holds.
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
        generation: HistoryGeneration,
        entries: &[NewArchiveEntry],
    ) -> Result<Archived, ArchiveStoreError> {
        // One transaction: the upload is whole or not at all, and its entries share `now()`.
        let mut tx = self.pool.begin().await.context("begin archive upload")?;
        let current = locked_generation(&mut tx, owner).await?;
        if check_history_generation(generation, current).is_err() {
            return Ok(Archived::Stale);
        }
        // One order for every upload: two holding the same entries take the index's locks in the
        // same order, so they can't deadlock (40P01).
        let mut ordered: Vec<&NewArchiveEntry> = entries.iter().collect();
        ordered.sort_by_key(|entry| entry.id);
        let mut stored = 0;
        for entry in ordered {
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
        Ok(Archived::Stored(
            usize::try_from(stored).unwrap_or_default(),
        ))
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
        Ok(erase(
            &mut *self.pool.acquire().await.context("clear an archive")?,
            owner,
        )
        .await?)
    }
}

/// The owner's current generation, its row share-locked until the transaction ends: a new
/// generation waits for the write checked against it, then erases what it wrote. Writers holding
/// the share lock don't wait for each other.
pub(super) async fn locked_generation(
    c: &mut PgConnection,
    owner: UserId,
) -> anyhow::Result<Option<HistoryGeneration>> {
    let current: Option<i32> =
        sqlx::query_scalar("SELECT generation FROM history_keys WHERE user_id = $1 FOR SHARE")
            .bind(owner.as_uuid())
            .fetch_optional(c)
            .await
            .context("read the history key's generation")?;
    current
        .map(|generation| HistoryGeneration::parse(generation.into()))
        .transpose()
        .context("history_keys.generation")
}

/// The owner's current generation, read without a lock.
pub(super) async fn current_generation(
    c: &mut PgConnection,
    owner: UserId,
) -> anyhow::Result<Option<HistoryGeneration>> {
    let current: Option<i32> =
        sqlx::query_scalar("SELECT generation FROM history_keys WHERE user_id = $1")
            .bind(owner.as_uuid())
            .fetch_optional(c)
            .await
            .context("read the history key's generation")?;
    current
        .map(|generation| HistoryGeneration::parse(generation.into()))
        .transpose()
        .context("history_keys.generation")
}

async fn erase(c: &mut PgConnection, owner: UserId) -> Result<usize, ArchiveStoreError> {
    let erased = sqlx::query("DELETE FROM history_messages WHERE user_id = $1")
        .bind(owner.as_uuid())
        .execute(c)
        .await
        .context("erase an archive")?
        .rows_affected();
    Ok(usize::try_from(erased).unwrap_or_default())
}

/// `history_keys`, whose replacement erases `history_messages` and `history_key_shares`, and ends
/// the open `start_over_requests`.
pub struct PgHistoryKeys {
    pool: PgPool,
}

impl PgHistoryKeys {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(sqlx::FromRow)]
struct KeyRow {
    generation: i32,
    salt: Vec<u8>,
    check_value: Vec<u8>,
    approval_public_key: Vec<u8>,
    set_by_device: Option<uuid::Uuid>,
}

impl TryFrom<KeyRow> for HeldHistoryKey {
    type Error = anyhow::Error;

    fn try_from(row: KeyRow) -> Result<Self, Self::Error> {
        Ok(HeldHistoryKey {
            key: HistoryKey {
                generation: HistoryGeneration::parse(row.generation.into())
                    .context("history_keys.generation")?,
                salt: HistorySalt::parse(&row.salt).context("history_keys.salt")?,
                check_value: HistoryCheckValue::parse(&row.check_value)
                    .context("history_keys.check_value")?,
                approval_public_key: ApprovalPublicKey::parse(&row.approval_public_key)
                    .context("history_keys.approval_public_key")?,
            },
            set_by: row.set_by_device.map(Into::into),
        })
    }
}

async fn held_for_update(
    c: &mut PgConnection,
    owner: UserId,
) -> anyhow::Result<Option<HeldHistoryKey>> {
    let row: Option<KeyRow> = sqlx::query_as(
        "SELECT generation, salt, check_value, approval_public_key, set_by_device \
         FROM history_keys WHERE user_id = $1 FOR UPDATE",
    )
    .bind(owner.as_uuid())
    .fetch_optional(c)
    .await
    .context("lock a history key")?;
    row.map(HeldHistoryKey::try_from).transpose()
}

async fn held(c: &mut PgConnection, owner: UserId) -> anyhow::Result<Option<HeldHistoryKey>> {
    let row: Option<KeyRow> = sqlx::query_as(
        "SELECT generation, salt, check_value, approval_public_key, set_by_device \
         FROM history_keys WHERE user_id = $1",
    )
    .bind(owner.as_uuid())
    .fetch_optional(c)
    .await
    .context("read a history key")?;
    row.map(HeldHistoryKey::try_from).transpose()
}

#[async_trait::async_trait]
impl HistoryKeys for PgHistoryKeys {
    async fn current(&self, owner: UserId) -> Result<Option<HeldHistoryKey>, ArchiveStoreError> {
        let mut c = self.pool.acquire().await.context("read a history key")?;
        Ok(held(&mut c, owner).await?)
    }

    async fn replace(
        &self,
        owner: UserId,
        key: &HistoryKey,
        set_by: DeviceId,
        now: OffsetDateTime,
    ) -> Result<KeyReplace, ArchiveStoreError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .context("begin history key replace")?;
        // The key's row first: a revoke, an approval's drop or another generation waits for it.
        let locked = held_for_update(&mut tx, owner).await?;
        let current = locked.as_ref().map(|held| held.key.generation);
        let trust = trust_facts(&mut tx, owner, current).await?;
        let open = locked_open(&mut tx, owner).await?;
        // A use committed before this read counts; one after it follows the write.
        let sessions = sessions_of(&mut tx, owner).await?;
        let gate = may_replace_history_key(
            key,
            set_by,
            locked.as_ref().map(|held| &held.key),
            &trust,
            open.as_ref(),
            &sessions,
            now,
        );
        let used = match gate {
            Ok(KeyGate::AlreadySet) => return Ok(KeyReplace::AlreadySet),
            Ok(KeyGate::Write(matured)) => matured.map(|matured| matured.request()),
            Err(ArchiveError::KeyConflict { current }) => return Ok(KeyReplace::Conflict(current)),
            Err(ArchiveError::StartOver(refusal)) => return Ok(KeyReplace::Refused(refusal)),
            Err(other) => return Err(ArchiveStoreError::Unexpected(other.into())),
        };
        let sql = match locked {
            None => {
                "INSERT INTO history_keys \
                     (user_id, generation, salt, check_value, approval_public_key, set_by_device) \
                 VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (user_id) DO NOTHING"
            }
            Some(_) => {
                "UPDATE history_keys SET generation = $2, salt = $3, check_value = $4, \
                     approval_public_key = $5, set_by_device = $6, set_at = now() \
                 WHERE user_id = $1"
            }
        };
        let written = sqlx::query(sql)
            .bind(owner.as_uuid())
            .bind(key.generation.value())
            .bind(key.salt.as_bytes())
            .bind(key.check_value.as_bytes())
            .bind(key.approval_public_key.as_bytes())
            .bind(set_by.as_uuid())
            .execute(&mut *tx)
            .await
            .context("write a history key")?
            .rows_affected();
        // No row to lock before the first: of two first keys at once, the second writes nothing.
        if written == 0 {
            return Ok(match held(&mut tx, owner).await? {
                Some(held) if held.key == *key => KeyReplace::AlreadySet,
                held => KeyReplace::Conflict(held.map(|held| held.key.generation)),
            });
        }
        let erased = erase(&mut tx, owner).await?;
        drop_older_passphrase_approvals(&mut tx, owner, key.generation).await?;
        delete_shares_of(&mut tx, owner).await?;
        let closed = end_with_generation(&mut tx, owner, used, now).await?;
        tx.commit().await.context("commit history key replace")?;
        Ok(KeyReplace::Replaced { erased, closed })
    }
}
