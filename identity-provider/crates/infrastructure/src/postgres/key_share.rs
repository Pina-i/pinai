use anyhow::Context;
use domain::e2ee::{
    Approver, CheckedShare, Deposit, Ed25519Signature, HistoryGeneration, KeyShare, KeyShares,
    KeyStoreError, SealedShare, ShareCiphertext, ShareEnc, check_history_generation,
};
use domain::{DeviceId, UserId};
use sqlx::{PgConnection, PgPool};
use time::OffsetDateTime;

use super::archive::locked_generation;

/// `history_key_shares`, whose rows a new generation of `history_keys`, a report, a revoke and a
/// new root key or HPKE key of `user_devices` delete.
pub struct PgKeyShares {
    pool: PgPool,
}

impl PgKeyShares {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(sqlx::FromRow)]
struct ShareRow {
    sender_device_id: uuid::Uuid,
    recipient_device_id: uuid::Uuid,
    generation: i32,
    enc: Vec<u8>,
    ciphertext: Vec<u8>,
    signature: Vec<u8>,
    created_at: OffsetDateTime,
}

impl TryFrom<ShareRow> for KeyShare {
    type Error = anyhow::Error;

    fn try_from(row: ShareRow) -> Result<Self, Self::Error> {
        Ok(KeyShare {
            sender: row.sender_device_id.into(),
            recipient: row.recipient_device_id.into(),
            generation: HistoryGeneration::parse(row.generation.into())
                .context("history_key_shares.generation")?,
            sealed: SealedShare {
                enc: ShareEnc::parse(&row.enc).context("history_key_shares.enc")?,
                ciphertext: ShareCiphertext::parse(row.ciphertext)
                    .context("history_key_shares.ciphertext")?,
                signature: Ed25519Signature::parse("signature", &row.signature)
                    .context("history_key_shares.signature")?,
            },
            created_at: row.created_at,
        })
    }
}

#[derive(sqlx::FromRow)]
struct HeldDevice {
    device_id: uuid::Uuid,
    drk_public_key: Option<Vec<u8>>,
    hpke_public_key: Option<Vec<u8>>,
    history_generation: Option<i32>,
}

/// Whether the share's devices — sender, recipient, and every device the approvals it relied on
/// name — are still as it was checked on, share-locked until the transaction ends, in one order,
/// before any approval row: a revoke, a new key or a report takes the device's row first too, so it
/// waits for the write, then deletes what it wrote.
async fn devices_hold(
    c: &mut PgConnection,
    owner: UserId,
    share: &CheckedShare,
) -> anyhow::Result<bool> {
    let mut ids = vec![share.sender().as_uuid(), share.recipient().as_uuid()];
    for approval in share.relied_on() {
        ids.push(approval.device.as_uuid());
        if let Approver::Device(approver) = approval.approver {
            ids.push(approver.as_uuid());
        }
    }
    let held: Vec<HeldDevice> = sqlx::query_as(
        "SELECT device_id, drk_public_key, hpke_public_key, history_generation FROM user_devices \
         WHERE device_id = ANY($1) AND user_id = $2 AND revoked_at IS NULL \
         ORDER BY device_id FOR SHARE",
    )
    .bind(&ids)
    .bind(owner.as_uuid())
    .fetch_all(&mut *c)
    .await
    .context("lock the devices of a share")?;
    let find = |id: DeviceId| held.iter().find(|device| device.device_id == id.as_uuid());
    let every_one_unrevoked = ids
        .iter()
        .all(|id| held.iter().any(|device| device.device_id == *id));
    let generation = Some(share.generation().value());
    let sender_holds = find(share.sender()).is_some_and(|device| {
        device.drk_public_key.as_deref() == Some(share.sender_key().as_bytes())
            && device.history_generation == generation
    });
    let recipient_holds = find(share.recipient()).is_some_and(|device| {
        device.drk_public_key.as_deref() == Some(share.recipient_key().as_bytes())
            && device.hpke_public_key.as_deref() == Some(share.recipient_hpke_key().as_bytes())
            && device.history_generation != generation
    });
    Ok(every_one_unrevoked && sender_holds && recipient_holds)
}

/// Whether every approval the share relied on is still held, share-locked as the devices are: a
/// drop waits for the write.
async fn approvals_hold(c: &mut PgConnection, share: &CheckedShare) -> anyhow::Result<bool> {
    for approval in share.relied_on() {
        let (approver, generation) = match approval.approver {
            Approver::Device(device) => (Some(device.as_uuid()), None),
            Approver::Passphrase(generation) => (None, Some(generation.value())),
        };
        let held: Option<i32> = sqlx::query_scalar(
            "SELECT 1 FROM device_approvals \
             WHERE device_id = $1 AND drk_public_key = $2 \
                 AND approver_device_id IS NOT DISTINCT FROM $3 \
                 AND generation IS NOT DISTINCT FROM $4 \
             FOR SHARE",
        )
        .bind(approval.device.as_uuid())
        .bind(approval.root_key.as_bytes())
        .bind(approver)
        .bind(generation)
        .fetch_optional(&mut *c)
        .await
        .context("lock an approval a share relied on")?;
        if held.is_none() {
            return Ok(false);
        }
    }
    Ok(true)
}

#[async_trait::async_trait]
impl KeyShares for PgKeyShares {
    async fn deposit(&self, owner: UserId, share: &CheckedShare) -> Result<Deposit, KeyStoreError> {
        let mut tx = self.pool.begin().await.context("begin a key share")?;
        let current = locked_generation(&mut tx, owner).await?;
        if check_history_generation(share.generation(), current).is_err()
            || !devices_hold(&mut tx, owner, share).await?
            || !approvals_hold(&mut tx, share).await?
        {
            return Ok(Deposit::Stale);
        }
        let sealed = share.sealed();
        let stored = sqlx::query(
            "INSERT INTO history_key_shares (user_id, recipient_device_id, generation, \
                 sender_device_id, enc, ciphertext, signature) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (recipient_device_id, generation) DO NOTHING",
        )
        .bind(owner.as_uuid())
        .bind(share.recipient().as_uuid())
        .bind(share.generation().value())
        .bind(share.sender().as_uuid())
        .bind(sealed.enc.as_bytes())
        .bind(sealed.ciphertext.as_bytes())
        .bind(sealed.signature.as_bytes())
        .execute(&mut *tx)
        .await
        .context("store a key share")?
        .rows_affected();
        tx.commit().await.context("commit a key share")?;
        Ok(if stored == 0 {
            Deposit::AlreadyHeld
        } else {
            Deposit::Stored
        })
    }

    async fn of_recipient(
        &self,
        owner: UserId,
        recipient: DeviceId,
        generation: HistoryGeneration,
    ) -> Result<Option<KeyShare>, KeyStoreError> {
        let row: Option<ShareRow> = sqlx::query_as(
            "SELECT sender_device_id, recipient_device_id, generation, enc, ciphertext, \
                 signature, created_at \
             FROM history_key_shares \
             WHERE user_id = $1 AND recipient_device_id = $2 AND generation = $3",
        )
        .bind(owner.as_uuid())
        .bind(recipient.as_uuid())
        .bind(generation.value())
        .fetch_optional(&self.pool)
        .await
        .context("read a key share")?;
        Ok(row.map(KeyShare::try_from).transpose()?)
    }
}

/// The owner's shares, which a new generation leaves sealing a passphrase no longer in use.
pub(super) async fn delete_shares_of(c: &mut PgConnection, owner: UserId) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM history_key_shares WHERE user_id = $1")
        .bind(owner.as_uuid())
        .execute(c)
        .await
        .context("delete an account's key shares")?;
    Ok(())
}

/// The shares sealed for `device`: held by it now, or no longer openable by it.
pub(super) async fn delete_shares_to(c: &mut PgConnection, device: DeviceId) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM history_key_shares WHERE recipient_device_id = $1")
        .bind(device.as_uuid())
        .execute(c)
        .await
        .context("delete the key shares sealed for a device")?;
    Ok(())
}

/// The shares `device` signed, which its revoke or a new root key leaves unverifiable.
pub(super) async fn delete_shares_from(
    c: &mut PgConnection,
    device: DeviceId,
) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM history_key_shares WHERE sender_device_id = $1")
        .bind(device.as_uuid())
        .execute(c)
        .await
        .context("delete the key shares a device sent")?;
    Ok(())
}
