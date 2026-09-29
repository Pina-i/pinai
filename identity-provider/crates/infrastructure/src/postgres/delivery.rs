use anyhow::Context;
use domain::e2ee::{
    Append, Commit, CommitBlob, CommitLog, DeliveryStoreError, Epoch, NewCommit, NewWelcome,
    Welcome, WelcomeBlob, Welcomes,
};
use domain::identity::ActorUri;
use domain::{ConversationId, DeviceId, UserId};
use sqlx::PgPool;
use time::OffsetDateTime;

/// `mls_commits`: `UNIQUE (conversation_id, epoch)` is the group's total order.
pub struct PgCommitLog {
    pool: PgPool,
}

impl PgCommitLog {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

const COMMIT_COLUMNS: &str =
    "id, conversation_id, epoch, commit_blob, proposer_actor_uri, created_at";

#[derive(sqlx::FromRow)]
struct CommitRow {
    id: uuid::Uuid,
    conversation_id: uuid::Uuid,
    epoch: i64,
    commit_blob: Vec<u8>,
    proposer_actor_uri: String,
    created_at: OffsetDateTime,
}

impl TryFrom<CommitRow> for Commit {
    type Error = anyhow::Error;

    fn try_from(row: CommitRow) -> Result<Self, Self::Error> {
        Ok(Commit {
            id: row.id.into(),
            conversation: row.conversation_id.into(),
            epoch: Epoch::parse(row.epoch).context("mls_commits.epoch")?,
            blob: CommitBlob::parse(row.commit_blob).context("mls_commits.commit_blob")?,
            proposer: ActorUri::parse(&row.proposer_actor_uri)
                .context("mls_commits.proposer_actor_uri")?,
            created_at: row.created_at,
        })
    }
}

#[async_trait::async_trait]
impl CommitLog for PgCommitLog {
    async fn append(&self, commit: &NewCommit) -> Result<Append, DeliveryStoreError> {
        let stored: Option<CommitRow> = sqlx::query_as(&format!(
            "INSERT INTO mls_commits (conversation_id, epoch, commit_blob, proposer_actor_uri) \
             VALUES ($1, $2, $3, $4) ON CONFLICT (conversation_id, epoch) DO NOTHING \
             RETURNING {COMMIT_COLUMNS}"
        ))
        .bind(commit.conversation.as_uuid())
        .bind(commit.epoch.value())
        .bind(commit.blob.as_bytes())
        .bind(commit.proposer.as_str())
        .fetch_optional(&self.pool)
        .await
        .context("append a commit")?;
        if let Some(row) = stored {
            return Ok(Append::Stored(Commit::try_from(row)?));
        }
        let winner: CommitRow = sqlx::query_as(&format!(
            "SELECT {COMMIT_COLUMNS} FROM mls_commits WHERE conversation_id = $1 AND epoch = $2"
        ))
        .bind(commit.conversation.as_uuid())
        .bind(commit.epoch.value())
        .fetch_one(&self.pool)
        .await
        .context("find the commit holding an epoch")?;
        Ok(Append::Taken(Commit::try_from(winner)?))
    }

    async fn since(
        &self,
        conversation: ConversationId,
        after: Epoch,
        limit: usize,
    ) -> Result<Vec<Commit>, DeliveryStoreError> {
        let rows: Vec<CommitRow> = sqlx::query_as(&format!(
            "SELECT {COMMIT_COLUMNS} FROM mls_commits \
             WHERE conversation_id = $1 AND epoch > $2 ORDER BY epoch LIMIT $3"
        ))
        .bind(conversation.as_uuid())
        .bind(after.value())
        .bind(i64::try_from(limit).unwrap_or(i64::MAX))
        .fetch_all(&self.pool)
        .await
        .context("catch up a group's commits")?;
        Ok(rows
            .into_iter()
            .map(Commit::try_from)
            .collect::<Result<_, _>>()?)
    }
}

/// `mls_welcomes`.
pub struct PgWelcomes {
    pool: PgPool,
}

impl PgWelcomes {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

const WELCOME_COLUMNS: &str =
    "id, recipient_user_id, recipient_device_id, conversation_id, welcome_blob, created_at";

#[derive(sqlx::FromRow)]
struct WelcomeRow {
    id: uuid::Uuid,
    recipient_user_id: uuid::Uuid,
    recipient_device_id: uuid::Uuid,
    conversation_id: uuid::Uuid,
    welcome_blob: Vec<u8>,
    created_at: OffsetDateTime,
}

impl TryFrom<WelcomeRow> for Welcome {
    type Error = anyhow::Error;

    fn try_from(row: WelcomeRow) -> Result<Self, Self::Error> {
        Ok(Welcome {
            id: row.id.into(),
            recipient: row.recipient_user_id.into(),
            device: row.recipient_device_id.into(),
            conversation: row.conversation_id.into(),
            blob: WelcomeBlob::parse(row.welcome_blob).context("mls_welcomes.welcome_blob")?,
            created_at: row.created_at,
        })
    }
}

#[async_trait::async_trait]
impl Welcomes for PgWelcomes {
    async fn deposit(&self, welcome: &NewWelcome) -> Result<Welcome, DeliveryStoreError> {
        let row: WelcomeRow = sqlx::query_as(&format!(
            "INSERT INTO mls_welcomes \
                 (recipient_user_id, recipient_device_id, conversation_id, welcome_blob) \
             VALUES ($1, $2, $3, $4) RETURNING {WELCOME_COLUMNS}"
        ))
        .bind(welcome.recipient.as_uuid())
        .bind(welcome.device.as_uuid())
        .bind(welcome.conversation.as_uuid())
        .bind(welcome.blob.as_bytes())
        .fetch_one(&self.pool)
        .await
        .context("deposit a Welcome")?;
        Ok(Welcome::try_from(row)?)
    }

    async fn claim(
        &self,
        recipient: UserId,
        device: DeviceId,
    ) -> Result<Vec<Welcome>, DeliveryStoreError> {
        // SKIP LOCKED: two concurrent fetches never both hand out the same Welcome.
        let rows: Vec<WelcomeRow> = sqlx::query_as(&format!(
            "UPDATE mls_welcomes SET consumed_at = now() \
             WHERE id IN ( \
                 SELECT id FROM mls_welcomes \
                 WHERE recipient_user_id = $1 AND recipient_device_id = $2 \
                   AND consumed_at IS NULL \
                 FOR UPDATE SKIP LOCKED) \
             RETURNING {WELCOME_COLUMNS}"
        ))
        .bind(recipient.as_uuid())
        .bind(device.as_uuid())
        .fetch_all(&self.pool)
        .await
        .context("claim a device's Welcomes")?;
        Ok(rows
            .into_iter()
            .map(Welcome::try_from)
            .collect::<Result<_, _>>()?)
    }

    async fn delete_claimed_before(
        &self,
        cutoff: OffsetDateTime,
    ) -> Result<usize, DeliveryStoreError> {
        let deleted = sqlx::query("DELETE FROM mls_welcomes WHERE consumed_at < $1")
            .bind(cutoff)
            .execute(&self.pool)
            .await
            .context("delete claimed Welcomes")?
            .rows_affected();
        Ok(usize::try_from(deleted).unwrap_or_default())
    }
}
