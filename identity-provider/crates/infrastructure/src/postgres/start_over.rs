use anyhow::Context;
use domain::e2ee::{
    HistoryGeneration, KeyStoreError, StartOverEnd, StartOverEnded, StartOverEnding,
    StartOverOpened, StartOverOpening, StartOverRefusal, StartOverRequest, StartOverRequests,
    may_open_start_over, start_over_window,
};
use domain::{DeviceId, StartOverRequestId, UserId};
use sqlx::{PgConnection, PgPool};
use time::OffsetDateTime;

use super::approval::{lock_unrevoked, trust_facts};
use super::archive::{current_generation, locked_generation};
use super::lock_account;

/// `start_over_requests`, whose open rows a revoke of their device and a new generation of
/// `history_keys` end.
pub struct PgStartOverRequests {
    pool: PgPool,
}

impl PgStartOverRequests {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

const COLUMNS: &str = "id, user_id, device_id, generation, created_at, ended_at, ended_reason";

#[derive(sqlx::FromRow)]
struct Row {
    id: uuid::Uuid,
    user_id: uuid::Uuid,
    device_id: uuid::Uuid,
    generation: i32,
    created_at: OffsetDateTime,
    ended_at: Option<OffsetDateTime>,
    ended_reason: Option<String>,
}

impl TryFrom<Row> for StartOverRequest {
    type Error = anyhow::Error;

    fn try_from(row: Row) -> Result<Self, Self::Error> {
        let ended = match (row.ended_at, row.ended_reason) {
            (None, None) => None,
            (Some(at), Some(reason)) => Some(StartOverEnding {
                how: reason
                    .parse::<StartOverEnd>()
                    .context("start_over_requests.ended_reason")?,
                at,
            }),
            _ => anyhow::bail!("start_over_requests {}: half an ending", row.id),
        };
        Ok(StartOverRequest {
            id: row.id.into(),
            owner: row.user_id.into(),
            device: row.device_id.into(),
            generation: HistoryGeneration::parse(row.generation.into())
                .context("start_over_requests.generation")?,
            created_at: row.created_at,
            ended,
        })
    }
}

fn requests(rows: Vec<Row>) -> anyhow::Result<Vec<StartOverRequest>> {
    rows.into_iter().map(StartOverRequest::try_from).collect()
}

async fn open_of(c: &mut PgConnection, owner: UserId) -> anyhow::Result<Option<StartOverRequest>> {
    let row: Option<Row> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM start_over_requests WHERE user_id = $1 AND ended_at IS NULL"
    ))
    .bind(owner.as_uuid())
    .fetch_optional(c)
    .await
    .context("read an account's open start over request")?;
    row.map(StartOverRequest::try_from).transpose()
}

/// The owner's request, row-locked until the transaction ends: an end and the write it allows
/// queue on it.
async fn locked(
    c: &mut PgConnection,
    owner: UserId,
    id: StartOverRequestId,
) -> anyhow::Result<Option<StartOverRequest>> {
    let row: Option<Row> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM start_over_requests WHERE id = $1 AND user_id = $2 FOR UPDATE"
    ))
    .bind(id.as_uuid())
    .bind(owner.as_uuid())
    .fetch_optional(c)
    .await
    .context("lock a start over request")?;
    row.map(StartOverRequest::try_from).transpose()
}

/// The account's open request, row-locked until the transaction ends: an end and the write that
/// uses it queue on it.
pub(super) async fn locked_open(
    c: &mut PgConnection,
    owner: UserId,
) -> anyhow::Result<Option<StartOverRequest>> {
    let row: Option<Row> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM start_over_requests \
         WHERE user_id = $1 AND ended_at IS NULL FOR UPDATE"
    ))
    .bind(owner.as_uuid())
    .fetch_optional(c)
    .await
    .context("lock an account's open start over request")?;
    row.map(StartOverRequest::try_from).transpose()
}

/// Ends `device`'s open request once the approval just written makes it approved under the
/// generation it would replace, at the approval's own time.
pub(super) async fn end_with_approval(
    c: &mut PgConnection,
    owner: UserId,
    device: DeviceId,
) -> anyhow::Result<Option<StartOverRequest>> {
    let open = locked_open(c, owner).await?;
    let Some(open) = open.filter(|open| open.device == device) else {
        return Ok(None);
    };
    let trust = trust_facts(c, owner, Some(open.generation)).await?;
    if trust.chain_under(device, open.generation).is_none() {
        return Ok(None);
    }
    let row: Row = sqlx::query_as(&format!(
        "UPDATE start_over_requests SET ended_at = now(), ended_reason = 'approved' \
         WHERE id = $1 RETURNING {COLUMNS}"
    ))
    .bind(open.id.as_uuid())
    .fetch_one(c)
    .await
    .context("end an approved device's start over request")?;
    Ok(Some(row.try_into()?))
}

/// Ends the owner's open requests in a new generation's write: `used`'s as used, any other as
/// superseded. Those superseded.
pub(super) async fn end_with_generation(
    c: &mut PgConnection,
    owner: UserId,
    used: Option<StartOverRequestId>,
    now: OffsetDateTime,
) -> anyhow::Result<Vec<StartOverRequest>> {
    let rows: Vec<Row> = sqlx::query_as(&format!(
        "UPDATE start_over_requests SET ended_at = $3, \
             ended_reason = CASE WHEN id = $2 THEN 'used' ELSE 'superseded' END \
         WHERE user_id = $1 AND ended_at IS NULL RETURNING {COLUMNS}"
    ))
    .bind(owner.as_uuid())
    .bind(used.map(|id| id.as_uuid()))
    .bind(now)
    .fetch_all(c)
    .await
    .context("end the open start over requests")?;
    Ok(requests(rows)?
        .into_iter()
        .filter(|request| Some(request.id) != used)
        .collect())
}

/// Cancels the request `device` has open, in its revoke's write.
pub(super) async fn end_with_revoke(
    c: &mut PgConnection,
    owner: UserId,
    device: DeviceId,
    now: OffsetDateTime,
) -> anyhow::Result<Option<StartOverRequest>> {
    let row: Option<Row> = sqlx::query_as(&format!(
        "UPDATE start_over_requests SET ended_at = $3, ended_reason = 'revoked' \
         WHERE user_id = $1 AND device_id = $2 AND ended_at IS NULL RETURNING {COLUMNS}"
    ))
    .bind(owner.as_uuid())
    .bind(device.as_uuid())
    .bind(now)
    .fetch_optional(c)
    .await
    .context("cancel a revoked device's start over request")?;
    row.map(StartOverRequest::try_from).transpose()
}

#[async_trait::async_trait]
impl StartOverRequests for PgStartOverRequests {
    async fn open(&self, request: &StartOverRequest) -> Result<StartOverOpened, KeyStoreError> {
        let owner = request.owner;
        let mut tx = self.pool.begin().await.context("begin a start over")?;
        // The key, then the device, then the account, as a new generation and a revoke take them.
        if locked_generation(&mut tx, owner).await? != Some(request.generation)
            || !lock_unrevoked(&mut tx, owner, request.device).await?
        {
            return Ok(StartOverOpened::Stale);
        }
        lock_account(&mut tx, owner).await?;
        let open = open_of(&mut tx, owner).await?;
        let opened: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM start_over_requests WHERE user_id = $1 AND created_at > $2",
        )
        .bind(owner.as_uuid())
        .bind(start_over_window(request.created_at))
        .fetch_one(&mut *tx)
        .await
        .context("count an account's start over requests")?;
        let opening = may_open_start_over(
            request,
            open.as_ref(),
            usize::try_from(opened).unwrap_or(usize::MAX),
        );
        match opening {
            Ok(StartOverOpening::Open) => {}
            Ok(StartOverOpening::Existing(existing)) => {
                return Ok(StartOverOpened::Existing(existing));
            }
            Err(refusal) => return Ok(StartOverOpened::Refused(refusal)),
        }
        let stored: Row = sqlx::query_as(&format!(
            "INSERT INTO start_over_requests (id, user_id, device_id, generation, created_at) \
             VALUES ($1, $2, $3, $4, $5) RETURNING {COLUMNS}"
        ))
        .bind(request.id.as_uuid())
        .bind(owner.as_uuid())
        .bind(request.device.as_uuid())
        .bind(request.generation.value())
        .bind(request.created_at)
        .fetch_one(&mut *tx)
        .await
        .context("open a start over request")?;
        tx.commit().await.context("commit a start over")?;
        Ok(StartOverOpened::Opened(stored.try_into()?))
    }

    async fn open_of(&self, owner: UserId) -> Result<Option<StartOverRequest>, KeyStoreError> {
        let mut c = self
            .pool
            .acquire()
            .await
            .context("read an open start over")?;
        Ok(open_of(&mut c, owner).await?)
    }

    async fn latest_of(
        &self,
        owner: UserId,
        device: DeviceId,
    ) -> Result<Option<StartOverRequest>, KeyStoreError> {
        let row: Option<Row> = sqlx::query_as(&format!(
            "SELECT {COLUMNS} FROM start_over_requests WHERE user_id = $1 AND device_id = $2 \
             ORDER BY created_at DESC, id LIMIT 1"
        ))
        .bind(owner.as_uuid())
        .bind(device.as_uuid())
        .fetch_optional(&self.pool)
        .await
        .context("read a device's latest start over request")?;
        Ok(row.map(StartOverRequest::try_from).transpose()?)
    }

    async fn request(
        &self,
        owner: UserId,
        id: StartOverRequestId,
    ) -> Result<Option<StartOverRequest>, KeyStoreError> {
        let row: Option<Row> = sqlx::query_as(&format!(
            "SELECT {COLUMNS} FROM start_over_requests WHERE id = $1 AND user_id = $2"
        ))
        .bind(id.as_uuid())
        .bind(owner.as_uuid())
        .fetch_optional(&self.pool)
        .await
        .context("read a start over request")?;
        Ok(row.map(StartOverRequest::try_from).transpose()?)
    }

    async fn end(
        &self,
        owner: UserId,
        id: StartOverRequestId,
        by: DeviceId,
        how: StartOverEnd,
        now: OffsetDateTime,
    ) -> Result<StartOverEnded, KeyStoreError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .context("begin ending a start over")?;
        if !lock_unrevoked(&mut tx, owner, by).await? {
            return Ok(StartOverEnded::Stale);
        }
        let Some(request) = locked(&mut tx, owner, id).await? else {
            return Ok(StartOverEnded::Refused(StartOverRefusal::NotFound));
        };
        if !request.is_open() {
            return Ok(StartOverEnded::Refused(StartOverRefusal::Ended));
        }
        let current = current_generation(&mut tx, owner).await?;
        let trust = trust_facts(&mut tx, owner, current).await?;
        if request.may_end(by, &trust).ok() != Some(how) {
            return Ok(StartOverEnded::Stale);
        }
        let ended: Row = sqlx::query_as(&format!(
            "UPDATE start_over_requests SET ended_at = $2, ended_reason = $3 WHERE id = $1 \
             RETURNING {COLUMNS}"
        ))
        .bind(id.as_uuid())
        .bind(now)
        .bind(how.as_str())
        .fetch_one(&mut *tx)
        .await
        .context("end a start over request")?;
        tx.commit().await.context("commit ending a start over")?;
        Ok(StartOverEnded::Ended(ended.try_into()?))
    }

    async fn delete_ended_before(&self, cutoff: OffsetDateTime) -> Result<usize, KeyStoreError> {
        let deleted = sqlx::query("DELETE FROM start_over_requests WHERE ended_at < $1")
            .bind(cutoff)
            .execute(&self.pool)
            .await
            .context("delete the start over requests that ended")?
            .rows_affected();
        Ok(usize::try_from(deleted).unwrap_or_default())
    }
}
