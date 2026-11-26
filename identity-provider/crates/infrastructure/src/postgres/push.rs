use anyhow::Context;
use domain::e2ee::{
    KeyStoreError, PushRegistration, PushRegistrations, PushRelay, PushToken, PushWrite,
    may_register_push,
};
use domain::{DeviceId, UserId};
use sqlx::{PgConnection, PgPool};
use time::OffsetDateTime;

use super::key_directory::locked_device;

/// `device_push_registrations`.
pub struct PgPushRegistrations {
    pool: PgPool,
}

impl PgPushRegistrations {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl PushRegistrations for PgPushRegistrations {
    async fn set(
        &self,
        owner: UserId,
        id: DeviceId,
        named: Option<DeviceId>,
        registration: &PushRegistration,
        now: OffsetDateTime,
    ) -> Result<PushWrite, KeyStoreError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .context("begin a push registration")?;
        let device = locked_device(&mut tx, id).await?;
        if let Err(refusal) = may_register_push(named, owner, id, device.as_ref()) {
            return Ok(PushWrite::Refused(refusal));
        }
        sqlx::query(
            "INSERT INTO device_push_registrations (device_id, user_id, relay, token, updated_at) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (device_id) DO UPDATE SET relay = EXCLUDED.relay, \
                 token = EXCLUDED.token, updated_at = EXCLUDED.updated_at",
        )
        .bind(id.as_uuid())
        .bind(owner.as_uuid())
        .bind(registration.relay.as_str())
        .bind(registration.token.as_str())
        .bind(now)
        .execute(&mut *tx)
        .await
        .context("set a push registration")?;
        tx.commit().await.context("commit a push registration")?;
        Ok(PushWrite::Done)
    }

    async fn remove(
        &self,
        owner: UserId,
        id: DeviceId,
        named: Option<DeviceId>,
    ) -> Result<PushWrite, KeyStoreError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .context("begin removing a push registration")?;
        let device = locked_device(&mut tx, id).await?;
        if let Err(refusal) = may_register_push(named, owner, id, device.as_ref()) {
            return Ok(PushWrite::Refused(refusal));
        }
        delete_push_registration(&mut tx, id).await?;
        tx.commit()
            .await
            .context("commit removing a push registration")?;
        Ok(PushWrite::Done)
    }

    async fn held(
        &self,
        owner: UserId,
    ) -> Result<Vec<(DeviceId, PushRegistration)>, KeyStoreError> {
        let rows: Vec<(uuid::Uuid, String, String)> = sqlx::query_as(
            "SELECT device_id, relay, token FROM device_push_registrations \
             WHERE user_id = $1 ORDER BY device_id",
        )
        .bind(owner.as_uuid())
        .fetch_all(&self.pool)
        .await
        .context("read an account's push registrations")?;
        let held = rows
            .into_iter()
            .map(|(id, relay, token)| -> anyhow::Result<_> {
                let registration = PushRegistration {
                    relay: PushRelay::parse(&relay).context("device_push_registrations.relay")?,
                    token: PushToken::parse(&token).context("device_push_registrations.token")?,
                };
                Ok((id.into(), registration))
            })
            .collect::<anyhow::Result<_>>()?;
        Ok(held)
    }
}

/// Within a revoke's write too: a revoked device is sent nothing.
pub(super) async fn delete_push_registration(
    c: &mut PgConnection,
    id: DeviceId,
) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM device_push_registrations WHERE device_id = $1")
        .bind(id.as_uuid())
        .execute(c)
        .await
        .context("delete a push registration")?;
    Ok(())
}
