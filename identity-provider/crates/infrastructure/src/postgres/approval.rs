use anyhow::Context;
use domain::e2ee::{
    Approval, ApprovalMessage, ApprovalMessageBody, ApprovalRequest, ApprovalRequests, Approve,
    Approver, CheckedApproval, Close, Device, DeviceApprovals, DeviceRootKey, DeviceTrust,
    Ed25519Signature, HistoryGeneration, KeyStoreError, MessageSeq, Opened, Post, Read,
    RequestRefusal, check_history_generation, may_open_request, window_start,
};
use domain::{ApprovalRequestId, DeviceId, UserId};
use sqlx::{PgConnection, PgPool};
use time::OffsetDateTime;

use super::archive::{current_generation, locked_generation};
use super::key_directory::devices_of;
use super::lock_account;
use super::start_over::end_with_approval;

/// `device_approvals`, whose rows the revoke and the root-key rotation of `user_devices` and a new
/// generation of `history_keys` drop.
pub struct PgDeviceApprovals {
    pool: PgPool,
}

impl PgDeviceApprovals {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(sqlx::FromRow)]
struct ApprovalRow {
    device_id: uuid::Uuid,
    drk_public_key: Vec<u8>,
    approver_device_id: Option<uuid::Uuid>,
    generation: Option<i32>,
    signature: Vec<u8>,
    created_at: OffsetDateTime,
}

impl TryFrom<ApprovalRow> for Approval {
    type Error = anyhow::Error;

    fn try_from(row: ApprovalRow) -> Result<Self, Self::Error> {
        let approver = match (row.approver_device_id, row.generation) {
            (Some(device), None) => Approver::Device(device.into()),
            (None, Some(generation)) => Approver::Passphrase(
                HistoryGeneration::parse(generation.into())
                    .context("device_approvals.generation")?,
            ),
            _ => anyhow::bail!("device_approvals of {}: no single approver", row.device_id),
        };
        Ok(Approval {
            device: row.device_id.into(),
            root_key: DeviceRootKey::parse(&row.drk_public_key)
                .context("device_approvals.drk_public_key")?,
            approver,
            signature: Ed25519Signature::parse("signature", &row.signature)
                .context("device_approvals.signature")?,
            created_at: row.created_at,
        })
    }
}

#[async_trait::async_trait]
impl DeviceApprovals for PgDeviceApprovals {
    async fn approve(
        &self,
        owner: UserId,
        approval: &CheckedApproval,
    ) -> Result<Approve, KeyStoreError> {
        let mut tx = self.pool.begin().await.context("begin an approval")?;
        let (approver_device, generation) = match approval.approver() {
            Approver::Device(device) => (Some(device), None),
            Approver::Passphrase(generation) => {
                let current = locked_generation(&mut tx, owner).await?;
                if check_history_generation(generation, current).is_err() {
                    return Ok(Approve::Stale);
                }
                (None, Some(generation))
            }
        };
        // Share-locked as checked: a revoke or a new root key waits for this write, then drops it.
        let mut ids = vec![approval.device().as_uuid()];
        ids.extend(approver_device.map(|device| device.as_uuid()));
        ids.sort();
        let held: Vec<(uuid::Uuid, Option<Vec<u8>>)> = sqlx::query_as(
            "SELECT device_id, drk_public_key FROM user_devices \
             WHERE device_id = ANY($1) AND user_id = $2 AND revoked_at IS NULL \
             ORDER BY device_id FOR SHARE",
        )
        .bind(&ids)
        .bind(owner.as_uuid())
        .fetch_all(&mut *tx)
        .await
        .context("lock the devices of an approval")?;
        let holds = |device: DeviceId, key: &DeviceRootKey| {
            held.iter()
                .any(|(id, drk)| *id == device.as_uuid() && drk.as_deref() == Some(key.as_bytes()))
        };
        let signer_holds = match (approver_device, approval.approver_key()) {
            (Some(device), Some(key)) => holds(device, key),
            (None, None) => true,
            _ => false,
        };
        if !signer_holds || !holds(approval.device(), approval.root_key()) {
            return Ok(Approve::Stale);
        }
        let recorded = sqlx::query(
            "INSERT INTO device_approvals \
                 (device_id, drk_public_key, approver_device_id, generation, signature) \
             VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
        )
        .bind(approval.device().as_uuid())
        .bind(approval.root_key().as_bytes())
        .bind(approver_device.map(|device| device.as_uuid()))
        .bind(generation.map(HistoryGeneration::value))
        .bind(approval.signature().as_bytes())
        .execute(&mut *tx)
        .await
        .context("record an approval")?
        .rows_affected();
        if recorded == 0 {
            return Ok(Approve::AlreadyHeld);
        }
        let start_over = end_with_approval(&mut tx, owner, approval.device()).await?;
        tx.commit().await.context("commit an approval")?;
        Ok(Approve::Recorded { start_over })
    }

    async fn of_owner(&self, owner: UserId) -> Result<Vec<Approval>, KeyStoreError> {
        let mut c = self
            .pool
            .acquire()
            .await
            .context("list an account's approvals")?;
        Ok(approvals_of(&mut c, owner).await?)
    }

    async fn trust(&self, owner: UserId) -> Result<DeviceTrust, KeyStoreError> {
        // Unlike every other read here, three statements that must agree: one snapshot.
        let mut tx = self.pool.begin().await.context("begin a trust read")?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            .execute(&mut *tx)
            .await
            .context("make a trust read one snapshot")?;
        let current = current_generation(&mut tx, owner).await?;
        let trust = trust_facts(&mut tx, owner, current).await?;
        tx.commit().await.context("end a trust read")?;
        Ok(trust)
    }
}

async fn approvals_of(c: &mut PgConnection, owner: UserId) -> anyhow::Result<Vec<Approval>> {
    let rows: Vec<ApprovalRow> = sqlx::query_as(
        "SELECT a.device_id, a.drk_public_key, a.approver_device_id, a.generation, \
             a.signature, a.created_at \
         FROM device_approvals a JOIN user_devices d ON d.device_id = a.device_id \
         WHERE d.user_id = $1 \
         ORDER BY a.created_at, a.device_id, a.approver_device_id NULLS FIRST, a.generation",
    )
    .bind(owner.as_uuid())
    .fetch_all(c)
    .await
    .context("list an account's approvals")?;
    rows.into_iter().map(Approval::try_from).collect()
}

/// The owner's devices and approvals under `current`, as the connection's transaction reads them.
pub(super) async fn trust_facts(
    c: &mut PgConnection,
    owner: UserId,
    current: Option<HistoryGeneration>,
) -> anyhow::Result<DeviceTrust> {
    Ok(DeviceTrust {
        devices: devices_of(c, owner).await?,
        approvals: approvals_of(c, owner).await?,
        current,
    })
}

/// The approvals a device signed, which its revoke, or a new root key, leaves unverifiable.
pub(super) async fn drop_approvals_by(
    c: &mut PgConnection,
    device: DeviceId,
) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM device_approvals WHERE approver_device_id = $1")
        .bind(device.as_uuid())
        .execute(c)
        .await
        .context("drop the approvals a device signed")?;
    Ok(())
}

/// The approvals of a device, which a new root key leaves unverifiable.
pub(super) async fn drop_approvals_of(
    c: &mut PgConnection,
    device: DeviceId,
) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM device_approvals WHERE device_id = $1")
        .bind(device.as_uuid())
        .execute(c)
        .await
        .context("drop a device's approvals")?;
    Ok(())
}

/// Closes the owner's requests `device` asks or answers: those still open, as they were closed.
pub(super) async fn close_requests_of(
    c: &mut PgConnection,
    owner: UserId,
    device: DeviceId,
    now: OffsetDateTime,
) -> anyhow::Result<Vec<ApprovalRequest>> {
    let closed: Vec<RequestRow> = sqlx::query_as(&format!(
        "UPDATE approval_requests SET closed_at = $3 \
         WHERE user_id = $1 AND closed_at IS NULL \
             AND (device_id = $2 OR approver_device_id = $2) \
         RETURNING {REQUEST_COLUMNS}, expires_at > $3 AS was_open"
    ))
    .bind(owner.as_uuid())
    .bind(device.as_uuid())
    .bind(now)
    .fetch_all(c)
    .await
    .context("close a device's requests")?;
    Ok(closed
        .into_iter()
        .filter(|row| row.was_open == Some(true))
        .map(Into::into)
        .collect())
}

/// The approvals of the owner's devices made with an approval key older than `generation`'s.
pub(super) async fn drop_older_passphrase_approvals(
    c: &mut PgConnection,
    owner: UserId,
    generation: HistoryGeneration,
) -> anyhow::Result<()> {
    sqlx::query(
        "DELETE FROM device_approvals a USING user_devices d \
         WHERE d.device_id = a.device_id AND d.user_id = $1 AND a.generation < $2",
    )
    .bind(owner.as_uuid())
    .bind(generation.value())
    .execute(c)
    .await
    .context("drop the approvals of older generations")?;
    Ok(())
}

/// `approval_requests` and `approval_messages`.
pub struct PgApprovalRequests {
    pool: PgPool,
}

impl PgApprovalRequests {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

const REQUEST_COLUMNS: &str =
    "id, user_id, device_id, approver_device_id, created_at, expires_at, closed_at";

#[derive(sqlx::FromRow)]
struct RequestRow {
    id: uuid::Uuid,
    user_id: uuid::Uuid,
    device_id: uuid::Uuid,
    approver_device_id: Option<uuid::Uuid>,
    created_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    closed_at: Option<OffsetDateTime>,
    #[sqlx(default)]
    was_open: Option<bool>,
}

impl From<RequestRow> for ApprovalRequest {
    fn from(row: RequestRow) -> Self {
        ApprovalRequest {
            id: row.id.into(),
            owner: row.user_id.into(),
            device: row.device_id.into(),
            approver: row.approver_device_id.map(Into::into),
            created_at: row.created_at,
            expires_at: row.expires_at,
            closed_at: row.closed_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct MessageRow {
    seq: i32,
    device_id: uuid::Uuid,
    body: Vec<u8>,
    created_at: OffsetDateTime,
}

impl TryFrom<MessageRow> for ApprovalMessage {
    type Error = anyhow::Error;

    fn try_from(row: MessageRow) -> Result<Self, Self::Error> {
        Ok(ApprovalMessage {
            seq: MessageSeq::parse(row.seq.into()).context("approval_messages.seq")?,
            from: row.device_id.into(),
            body: ApprovalMessageBody::parse(row.body).context("approval_messages.body")?,
            created_at: row.created_at,
        })
    }
}

/// Share-locks the owner's device while it is unrevoked: a revoke, which takes the row first too,
/// waits for the write, then closes what it opened or bound. `false` when it is revoked already.
pub(super) async fn lock_unrevoked(
    c: &mut PgConnection,
    owner: UserId,
    device: DeviceId,
) -> anyhow::Result<bool> {
    let locked: Option<i32> = sqlx::query_scalar(
        "SELECT 1 FROM user_devices \
         WHERE device_id = $1 AND user_id = $2 AND revoked_at IS NULL FOR SHARE",
    )
    .bind(device.as_uuid())
    .bind(owner.as_uuid())
    .fetch_optional(c)
    .await
    .context("lock the acting device")?;
    Ok(locked.is_some())
}

/// The owner's request, row-locked until the transaction ends: posts and closes queue on it.
async fn locked_request(
    c: &mut PgConnection,
    owner: UserId,
    id: ApprovalRequestId,
) -> anyhow::Result<Option<ApprovalRequest>> {
    let row: Option<RequestRow> = sqlx::query_as(&format!(
        "SELECT {REQUEST_COLUMNS} FROM approval_requests WHERE id = $1 AND user_id = $2 FOR UPDATE"
    ))
    .bind(id.as_uuid())
    .bind(owner.as_uuid())
    .fetch_optional(c)
    .await
    .context("lock an approval request")?;
    Ok(row.map(Into::into))
}

#[async_trait::async_trait]
impl ApprovalRequests for PgApprovalRequests {
    async fn open(&self, request: &ApprovalRequest) -> Result<Opened, KeyStoreError> {
        let now = request.created_at;
        let mut tx = self.pool.begin().await.context("begin opening a request")?;
        if !lock_unrevoked(&mut tx, request.owner, request.device).await? {
            return Ok(Opened::Stale);
        }
        // The account's lock: two opening at once are counted one after the other.
        lock_account(&mut tx, request.owner).await?;
        let opened: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM approval_requests WHERE user_id = $1 AND created_at > $2",
        )
        .bind(request.owner.as_uuid())
        .bind(window_start(now))
        .fetch_one(&mut *tx)
        .await
        .context("count an account's requests")?;
        if may_open_request(usize::try_from(opened).unwrap_or(usize::MAX)).is_err() {
            return Ok(Opened::TooMany);
        }
        let closed: Vec<RequestRow> = sqlx::query_as(&format!(
            "UPDATE approval_requests SET closed_at = $2 \
             WHERE device_id = $1 AND closed_at IS NULL RETURNING {REQUEST_COLUMNS}"
        ))
        .bind(request.device.as_uuid())
        .bind(now)
        .fetch_all(&mut *tx)
        .await
        .context("close a device's open request")?;
        sqlx::query(
            "INSERT INTO approval_requests \
                 (id, user_id, device_id, approver_device_id, created_at, expires_at, closed_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(request.id.as_uuid())
        .bind(request.owner.as_uuid())
        .bind(request.device.as_uuid())
        .bind(request.approver.map(|device| device.as_uuid()))
        .bind(request.created_at)
        .bind(request.expires_at)
        .bind(request.closed_at)
        .execute(&mut *tx)
        .await
        .context("open a request")?;
        tx.commit().await.context("commit opening a request")?;
        Ok(Opened::Opened {
            closed: closed
                .into_iter()
                .map(ApprovalRequest::from)
                .filter(|earlier| now < earlier.expires_at)
                .collect(),
        })
    }

    async fn open_of(
        &self,
        owner: UserId,
        now: OffsetDateTime,
    ) -> Result<Vec<ApprovalRequest>, KeyStoreError> {
        let rows: Vec<RequestRow> = sqlx::query_as(&format!(
            "SELECT {REQUEST_COLUMNS} FROM approval_requests \
             WHERE user_id = $1 AND closed_at IS NULL AND expires_at > $2 \
             ORDER BY created_at, id"
        ))
        .bind(owner.as_uuid())
        .bind(now)
        .fetch_all(&self.pool)
        .await
        .context("list an account's open requests")?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn post(
        &self,
        owner: UserId,
        id: ApprovalRequestId,
        from: &Device,
        body: &ApprovalMessageBody,
        now: OffsetDateTime,
    ) -> Result<Post, KeyStoreError> {
        let mut tx = self.pool.begin().await.context("begin a post")?;
        if !lock_unrevoked(&mut tx, owner, from.id).await? {
            return Ok(Post::Stale);
        }
        let Some(mut request) = locked_request(&mut tx, owner, id).await? else {
            return Ok(Post::Refused(RequestRefusal::NotFound));
        };
        let posted: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM approval_messages WHERE request_id = $1")
                .bind(id.as_uuid())
                .fetch_one(&mut *tx)
                .await
                .context("count a request's messages")?;
        let posting =
            match request.may_post(from, usize::try_from(posted).unwrap_or(usize::MAX), now) {
                Ok(posting) => posting,
                Err(refusal) => return Ok(Post::Refused(refusal)),
            };
        if posting.binds {
            sqlx::query("UPDATE approval_requests SET approver_device_id = $2 WHERE id = $1")
                .bind(id.as_uuid())
                .bind(from.id.as_uuid())
                .execute(&mut *tx)
                .await
                .context("bind a request to its approver")?;
            request.approver = Some(from.id);
        }
        sqlx::query(
            "INSERT INTO approval_messages (request_id, seq, device_id, body, created_at) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(id.as_uuid())
        .bind(posting.seq.value())
        .bind(from.id.as_uuid())
        .bind(body.as_bytes())
        .bind(now)
        .execute(&mut *tx)
        .await
        .context("post to a request")?;
        tx.commit().await.context("commit a post")?;
        Ok(Post::Posted {
            request,
            seq: posting.seq,
            bound: posting.binds,
        })
    }

    async fn read(
        &self,
        owner: UserId,
        id: ApprovalRequestId,
        reader: DeviceId,
        after: MessageSeq,
        now: OffsetDateTime,
    ) -> Result<Read, KeyStoreError> {
        let mut tx = self.pool.begin().await.context("begin a read")?;
        // Shared: a post binding the request meanwhile is read as it left it.
        let row: Option<RequestRow> = sqlx::query_as(&format!(
            "SELECT {REQUEST_COLUMNS} FROM approval_requests \
             WHERE id = $1 AND user_id = $2 FOR SHARE"
        ))
        .bind(id.as_uuid())
        .bind(owner.as_uuid())
        .fetch_optional(&mut *tx)
        .await
        .context("read an approval request")?;
        let Some(request) = row.map(ApprovalRequest::from) else {
            return Ok(Read::Refused(RequestRefusal::NotFound));
        };
        if let Err(refusal) = request.may_read(reader, now) {
            return Ok(Read::Refused(refusal));
        }
        let rows: Vec<MessageRow> = sqlx::query_as(
            "SELECT seq, device_id, body, created_at FROM approval_messages \
             WHERE request_id = $1 AND seq > $2 AND device_id <> $3 ORDER BY seq",
        )
        .bind(id.as_uuid())
        .bind(after.value())
        .bind(reader.as_uuid())
        .fetch_all(&mut *tx)
        .await
        .context("read a request's messages")?;
        tx.commit().await.context("end a read")?;
        Ok(Read::Messages(
            rows.into_iter()
                .map(ApprovalMessage::try_from)
                .collect::<Result<_, _>>()?,
        ))
    }

    async fn close(
        &self,
        owner: UserId,
        id: ApprovalRequestId,
        by: DeviceId,
        now: OffsetDateTime,
    ) -> Result<Close, KeyStoreError> {
        let mut tx = self.pool.begin().await.context("begin a close")?;
        let Some(mut request) = locked_request(&mut tx, owner, id).await? else {
            return Ok(Close::Refused(RequestRefusal::NotFound));
        };
        if let Err(refusal) = request.may_take_part(by, now) {
            return Ok(Close::Refused(refusal));
        }
        sqlx::query("UPDATE approval_requests SET closed_at = $2 WHERE id = $1")
            .bind(id.as_uuid())
            .bind(now)
            .execute(&mut *tx)
            .await
            .context("close a request")?;
        tx.commit().await.context("commit a close")?;
        request.closed_at = Some(now);
        Ok(Close::Closed(request))
    }

    async fn delete_opened_before(&self, cutoff: OffsetDateTime) -> Result<usize, KeyStoreError> {
        let deleted = sqlx::query("DELETE FROM approval_requests WHERE created_at < $1")
            .bind(cutoff)
            .execute(&self.pool)
            .await
            .context("delete old approval requests")?
            .rows_affected();
        Ok(usize::try_from(deleted).unwrap_or_default())
    }
}
