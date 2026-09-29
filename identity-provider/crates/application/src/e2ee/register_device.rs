use std::sync::Arc;

use domain::e2ee::{
    ATTESTATION_LIFETIME, Attestation, DeviceAttester, DeviceLabel, DeviceNotifier, DeviceRootKey,
    Devices, KeyDirectoryError, Registration, SignedAttestation,
};
use domain::identity::Accounts;
use domain::{DeviceId, UserId};
use time::OffsetDateTime;

pub struct Registered {
    pub signed: SignedAttestation,
    pub issued_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

/// `POST /api/keys/devices`: attest a device's root key — the first time, again to renew it, or
/// another key to rotate.
pub struct RegisterDevice {
    accounts: Arc<dyn Accounts>,
    devices: Arc<dyn Devices>,
    attester: Arc<dyn DeviceAttester>,
    notifier: Arc<dyn DeviceNotifier>,
}

impl RegisterDevice {
    pub fn new(
        accounts: Arc<dyn Accounts>,
        devices: Arc<dyn Devices>,
        attester: Arc<dyn DeviceAttester>,
        notifier: Arc<dyn DeviceNotifier>,
    ) -> Self {
        Self {
            accounts,
            devices,
            attester,
            notifier,
        }
    }

    pub async fn execute(
        &self,
        owner: UserId,
        device: DeviceId,
        key: DeviceRootKey,
        now: OffsetDateTime,
    ) -> Result<Registered, KeyDirectoryError> {
        let account = self.accounts.find(owner).await?.ok_or_else(|| {
            KeyDirectoryError::Unexpected(anyhow::anyhow!("the registering account is gone"))
        })?;
        let existing = self.devices.find(device).await?;
        let registration = Registration::of(existing.as_ref(), owner, &key)?;
        if registration == Registration::Rotation {
            tracing::warn!(%device, "device root key rotated: KeyPackages under the old key stop verifying");
        }
        let expires_at = now + ATTESTATION_LIFETIME;
        let signed = self
            .attester
            .attest(&account.actor_uri, device, &key, expires_at);
        let attestation = Attestation {
            root_key: key,
            signature: signed.signature.clone(),
            kid: signed.kid.clone(),
            issued_at: now,
            expires_at,
        };
        // A device registering before it publishes any KeyPackage is not known yet.
        self.devices
            .attest(owner, device, &DeviceLabel::unknown(), &attestation)
            .await?;
        if registration == Registration::FirstTime {
            self.notifier
                .device_joined(owner, &account.actor_uri, device, &attestation.root_key);
        }
        Ok(Registered {
            signed,
            issued_at: now,
            expires_at,
        })
    }
}
