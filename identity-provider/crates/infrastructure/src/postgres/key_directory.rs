use anyhow::Context;
use domain::e2ee::{
    Attestation, ClaimedKeyPackage, Device, DeviceLabel, DeviceRootKey, Devices, KeyPackageBytes,
    KeyPackages, KeyStoreError, NewKeyPackage, Revocation,
};
use domain::{DeviceId, UserId};
use sqlx::{PgConnection, PgPool};
use time::OffsetDateTime;

/// `user_devices`.
pub struct PgDevices {
    pool: PgPool,
}

impl PgDevices {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

const DEVICE_COLUMNS: &str = "device_id, user_id, display_name, kind, paired_at, last_seen_at, \
     revoked_at, drk_public_key, attestation_signature, attestation_kid, attestation_issued_at, \
     attestation_expires_at";

#[derive(sqlx::FromRow)]
struct DeviceRow {
    device_id: uuid::Uuid,
    user_id: uuid::Uuid,
    display_name: String,
    kind: String,
    paired_at: OffsetDateTime,
    last_seen_at: OffsetDateTime,
    revoked_at: Option<OffsetDateTime>,
    drk_public_key: Option<Vec<u8>>,
    attestation_signature: Option<Vec<u8>>,
    attestation_kid: Option<String>,
    attestation_issued_at: Option<OffsetDateTime>,
    attestation_expires_at: Option<OffsetDateTime>,
}

impl TryFrom<DeviceRow> for Device {
    type Error = anyhow::Error;

    fn try_from(row: DeviceRow) -> Result<Self, Self::Error> {
        let attestation = match (
            row.drk_public_key,
            row.attestation_signature,
            row.attestation_kid,
            row.attestation_issued_at,
            row.attestation_expires_at,
        ) {
            (None, None, None, None, None) => None,
            (Some(key), Some(signature), Some(kid), Some(issued_at), Some(expires_at)) => {
                Some(Attestation {
                    root_key: DeviceRootKey::parse(&key).context("user_devices.drk_public_key")?,
                    signature,
                    kid,
                    issued_at,
                    expires_at,
                })
            }
            _ => anyhow::bail!("user_devices {}: a partial attestation", row.device_id),
        };
        Ok(Device {
            id: row.device_id.into(),
            owner: row.user_id.into(),
            label: DeviceLabel {
                name: row.display_name,
                kind: row.kind.parse().context("user_devices.kind")?,
            },
            paired_at: row.paired_at,
            last_seen_at: row.last_seen_at,
            revoked_at: row.revoked_at,
            attestation,
        })
    }
}

/// Records a device not seen before under `label`, or marks it seen — a known one keeps its
/// name. `DeviceTaken` when another account holds the id: the guarded upsert touches no row.
async fn record_device(
    c: &mut PgConnection,
    owner: UserId,
    id: DeviceId,
    label: &DeviceLabel,
) -> Result<(), KeyStoreError> {
    let recorded = sqlx::query(
        "INSERT INTO user_devices (device_id, user_id, display_name, kind) \
         VALUES ($1, $2, $3, $4) \
         ON CONFLICT (device_id) DO UPDATE SET last_seen_at = NOW() \
         WHERE user_devices.user_id = EXCLUDED.user_id",
    )
    .bind(id.as_uuid())
    .bind(owner.as_uuid())
    .bind(&label.name)
    .bind(label.kind.as_str())
    .execute(&mut *c)
    .await
    .context("record a device")?
    .rows_affected();
    if recorded == 0 {
        return Err(KeyStoreError::DeviceTaken);
    }
    Ok(())
}

#[async_trait::async_trait]
impl Devices for PgDevices {
    async fn find(&self, id: DeviceId) -> Result<Option<Device>, KeyStoreError> {
        let row: Option<DeviceRow> = sqlx::query_as(&format!(
            "SELECT {DEVICE_COLUMNS} FROM user_devices WHERE device_id = $1"
        ))
        .bind(id.as_uuid())
        .fetch_optional(&self.pool)
        .await
        .context("find a device")?;
        Ok(row.map(Device::try_from).transpose()?)
    }

    async fn list(&self, owner: UserId) -> Result<Vec<Device>, KeyStoreError> {
        let rows: Vec<DeviceRow> = sqlx::query_as(&format!(
            "SELECT {DEVICE_COLUMNS} FROM user_devices WHERE user_id = $1 \
             ORDER BY (revoked_at IS NOT NULL), last_seen_at DESC"
        ))
        .bind(owner.as_uuid())
        .fetch_all(&self.pool)
        .await
        .context("list a user's devices")?;
        Ok(rows
            .into_iter()
            .map(Device::try_from)
            .collect::<Result<_, _>>()?)
    }

    async fn attest(
        &self,
        owner: UserId,
        id: DeviceId,
        label: &DeviceLabel,
        attestation: &Attestation,
    ) -> Result<(), KeyStoreError> {
        let mut tx = self.pool.begin().await.context("begin attest")?;
        sqlx::query(
            "INSERT INTO user_devices (device_id, user_id, display_name, kind) \
             VALUES ($1, $2, $3, $4) ON CONFLICT (device_id) DO NOTHING",
        )
        .bind(id.as_uuid())
        .bind(owner.as_uuid())
        .bind(&label.name)
        .bind(label.kind.as_str())
        .execute(&mut *tx)
        .await
        .context("record a device")?;
        let attested = sqlx::query(
            "UPDATE user_devices SET drk_public_key = $3, attestation_signature = $4, \
                 attestation_kid = $5, attestation_issued_at = $6, attestation_expires_at = $7 \
             WHERE device_id = $1 AND user_id = $2",
        )
        .bind(id.as_uuid())
        .bind(owner.as_uuid())
        .bind(attestation.root_key.as_bytes())
        .bind(&attestation.signature)
        .bind(&attestation.kid)
        .bind(attestation.issued_at)
        .bind(attestation.expires_at)
        .execute(&mut *tx)
        .await
        .context("store an attestation")?
        .rows_affected();
        if attested == 0 {
            return Err(KeyStoreError::DeviceTaken);
        }
        tx.commit().await.context("commit attest")?;
        Ok(())
    }

    async fn revoke(&self, owner: UserId, id: DeviceId) -> Result<Revocation, KeyStoreError> {
        let revoked = sqlx::query(
            "UPDATE user_devices SET revoked_at = NOW() \
             WHERE device_id = $1 AND user_id = $2 AND revoked_at IS NULL",
        )
        .bind(id.as_uuid())
        .bind(owner.as_uuid())
        .execute(&self.pool)
        .await
        .context("revoke a device")?
        .rows_affected();
        if revoked > 0 {
            return Ok(Revocation::Revoked);
        }
        let owned: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM user_devices WHERE device_id = $1 AND user_id = $2)",
        )
        .bind(id.as_uuid())
        .bind(owner.as_uuid())
        .fetch_one(&self.pool)
        .await
        .context("find a device to revoke")?;
        Ok(if owned {
            Revocation::AlreadyRevoked
        } else {
            Revocation::NotFound
        })
    }
}

/// `key_packages`.
pub struct PgKeyPackages {
    pool: PgPool,
}

impl PgKeyPackages {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

fn count(n: i64) -> usize {
    usize::try_from(n).unwrap_or_default()
}

#[async_trait::async_trait]
impl KeyPackages for PgKeyPackages {
    async fn available(&self, owner: UserId, device: DeviceId) -> Result<usize, KeyStoreError> {
        let n: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM key_packages \
             WHERE user_id = $1 AND device_id = $2 AND consumed_at IS NULL AND expires_at > now()",
        )
        .bind(owner.as_uuid())
        .bind(device.as_uuid())
        .fetch_one(&self.pool)
        .await
        .context("count a device's KeyPackages")?;
        Ok(count(n))
    }

    async fn available_per_device(
        &self,
        owner: UserId,
    ) -> Result<Vec<(DeviceId, usize)>, KeyStoreError> {
        let rows: Vec<(uuid::Uuid, i64)> = sqlx::query_as(
            "SELECT device_id, COUNT(*) FROM key_packages \
             WHERE user_id = $1 AND consumed_at IS NULL AND expires_at > now() \
             GROUP BY device_id",
        )
        .bind(owner.as_uuid())
        .fetch_all(&self.pool)
        .await
        .context("count KeyPackages per device")?;
        Ok(rows
            .into_iter()
            .map(|(device, n)| (device.into(), count(n)))
            .collect())
    }

    async fn stash(
        &self,
        owner: UserId,
        device: DeviceId,
        label: &DeviceLabel,
        packages: &[NewKeyPackage],
    ) -> Result<usize, KeyStoreError> {
        let blobs: Vec<&[u8]> = packages.iter().map(|p| p.bytes.as_bytes()).collect();
        let expiries: Vec<OffsetDateTime> = packages.iter().map(|p| p.expires_at).collect();
        let mut tx = self.pool.begin().await.context("begin stash")?;
        let stored = sqlx::query(
            "INSERT INTO key_packages (user_id, device_id, key_package, expires_at) \
             SELECT $1, $2, blob, expires FROM UNNEST($3::bytea[], $4::timestamptz[]) AS t(blob, expires)",
        )
        .bind(owner.as_uuid())
        .bind(device.as_uuid())
        .bind(blobs)
        .bind(expiries)
        .execute(&mut *tx)
        .await
        .context("stash KeyPackages")?
        .rows_affected();
        record_device(&mut tx, owner, device, label).await?;
        tx.commit().await.context("commit stash")?;
        Ok(usize::try_from(stored).unwrap_or_default())
    }

    async fn claim(
        &self,
        owner: UserId,
        device: Option<DeviceId>,
    ) -> Result<Option<ClaimedKeyPackage>, KeyStoreError> {
        // SKIP LOCKED: concurrent claimers each take a different row instead of queueing.
        let row: Option<(uuid::Uuid, Vec<u8>, OffsetDateTime)> = sqlx::query_as(
            "UPDATE key_packages SET consumed_at = now() \
             WHERE id = ( \
                 SELECT id FROM key_packages \
                 WHERE user_id = $1 AND ($2::uuid IS NULL OR device_id = $2) \
                   AND consumed_at IS NULL AND expires_at > now() \
                   AND NOT EXISTS (SELECT 1 FROM user_devices d \
                       WHERE d.device_id = key_packages.device_id AND d.revoked_at IS NOT NULL) \
                 ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED) \
             RETURNING device_id, key_package, expires_at",
        )
        .bind(owner.as_uuid())
        .bind(device.map(|d| d.as_uuid()))
        .fetch_optional(&self.pool)
        .await
        .context("claim a KeyPackage")?;
        row.map(|(device, bytes, expires_at)| {
            Ok(ClaimedKeyPackage {
                device: device.into(),
                bytes: KeyPackageBytes::parse(bytes).context("key_packages.key_package")?,
                expires_at,
            })
        })
        .transpose()
    }

    async fn delete_spent(
        &self,
        expired_before: OffsetDateTime,
        claimed_before: OffsetDateTime,
    ) -> Result<usize, KeyStoreError> {
        let deleted =
            sqlx::query("DELETE FROM key_packages WHERE expires_at < $1 OR consumed_at < $2")
                .bind(expired_before)
                .bind(claimed_before)
                .execute(&self.pool)
                .await
                .context("delete spent KeyPackages")?
                .rows_affected();
        Ok(usize::try_from(deleted).unwrap_or_default())
    }
}
