use std::sync::Arc;

use domain::DeviceId;
use domain::auth::Sessions;
use domain::e2ee::{
    Attest, Attestation, DeviceAttester, DeviceLabel, DeviceNotifier, DeviceRootKey, Devices,
    KeyDirectoryError, Registration, RootKeyVerifier, SignedAttestation, UnverifiedHpkeKey,
    attestation_period, may_register,
};
use domain::identity::{Accounts, Bearer};
use time::OffsetDateTime;

/// A revoke or another registration may land between the read and the write: each attempt reads
/// the device again.
const ATTEMPTS: usize = 3;

pub struct Registered {
    pub signed: SignedAttestation,
    pub issued_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

/// `POST /api/keys/devices`: attest a device's root key — the first time, again to renew it, or
/// another key to rotate — with the HPKE key it signed, when it sends one.
pub struct RegisterDevice {
    accounts: Arc<dyn Accounts>,
    devices: Arc<dyn Devices>,
    attester: Arc<dyn DeviceAttester>,
    verifier: Arc<dyn RootKeyVerifier>,
    sessions: Arc<dyn Sessions>,
    notifier: Arc<dyn DeviceNotifier>,
}

impl RegisterDevice {
    pub fn new(
        accounts: Arc<dyn Accounts>,
        devices: Arc<dyn Devices>,
        attester: Arc<dyn DeviceAttester>,
        verifier: Arc<dyn RootKeyVerifier>,
        sessions: Arc<dyn Sessions>,
        notifier: Arc<dyn DeviceNotifier>,
    ) -> Self {
        Self {
            accounts,
            devices,
            attester,
            verifier,
            sessions,
            notifier,
        }
    }

    pub async fn execute(
        &self,
        bearer: &Bearer,
        device: DeviceId,
        key: DeviceRootKey,
        brought: Option<UnverifiedHpkeKey>,
        now: OffsetDateTime,
    ) -> Result<Registered, KeyDirectoryError> {
        let owner = bearer.user;
        let session = self
            .sessions
            .find(bearer.session)
            .await
            .map_err(|e| KeyDirectoryError::Unexpected(e.into()))?
            .ok_or_else(|| {
                KeyDirectoryError::Unexpected(anyhow::anyhow!("the registering session is gone"))
            })?;
        may_register(session.device, device)?;
        let account = self.accounts.find(owner).await?.ok_or_else(|| {
            KeyDirectoryError::Unexpected(anyhow::anyhow!("the registering account is gone"))
        })?;
        let brought = brought
            .map(|brought| brought.verified(&key, &account.actor_uri, device, &*self.verifier))
            .transpose()?;
        let (issued_at, expires_at) = attestation_period(now);
        let signed = self
            .attester
            .attest(&account.actor_uri, device, &key, expires_at);
        let attestation = Attestation {
            root_key: key,
            signature: signed.signature.clone(),
            kid: signed.kid.clone(),
            issued_at,
            expires_at: expires_at.at(),
        };
        for _ in 0..ATTEMPTS {
            let existing = self.devices.find(device).await?;
            let registration = Registration::of(existing.as_ref(), owner, &attestation.root_key)?;
            let hpke_key = registration.hpke_key(brought.clone());
            // A device registering before it publishes any KeyPackage is not known yet.
            let written = self
                .devices
                .attest(
                    owner,
                    device,
                    &DeviceLabel::unknown(),
                    existing.as_ref(),
                    &attestation,
                    &hpke_key,
                )
                .await?;
            if written == Attest::Stale {
                continue;
            }
            match registration {
                Registration::FirstTime => self.notifier.device_joined(
                    owner,
                    &account.actor_uri,
                    device,
                    &attestation.root_key,
                ),
                Registration::Rotation => {
                    tracing::warn!(%device, "device root key rotated: KeyPackages under the old key stop verifying");
                }
                Registration::Renewal => {}
            }
            return Ok(Registered {
                signed,
                issued_at,
                expires_at: expires_at.at(),
            });
        }
        Err(KeyDirectoryError::Unexpected(anyhow::anyhow!(
            "device {device} kept changing while it registered"
        )))
    }
}
