use std::sync::Arc;

use domain::auth::{SessionNotifier, Sessions};
use domain::e2ee::{Devices, KeyDirectoryError, Revocation};
use domain::{DeviceId, UserId};
use time::OffsetDateTime;

use crate::auth::tell_ended;

/// `POST /api/keys/devices/{id}/revoke`: the device is signed out — its sessions end, their
/// tokens and sockets with them — and flagged in the directory; the MLS Remove commits that
/// exclude it are the clients'. Revoking twice is fine.
pub struct RevokeDevice {
    devices: Arc<dyn Devices>,
    sessions: Arc<dyn Sessions>,
    notifier: Arc<dyn SessionNotifier>,
}

impl RevokeDevice {
    pub fn new(
        devices: Arc<dyn Devices>,
        sessions: Arc<dyn Sessions>,
        notifier: Arc<dyn SessionNotifier>,
    ) -> Self {
        Self {
            devices,
            sessions,
            notifier,
        }
    }

    /// `DeviceNotFound` for a device that is not the owner's, so others' ids never leak.
    pub async fn execute(
        &self,
        owner: UserId,
        device: DeviceId,
        now: OffsetDateTime,
    ) -> Result<(), KeyDirectoryError> {
        // Signed out before the flag: should the flag fail, the device is out all the same,
        // and revoking again finishes.
        let ended = self
            .sessions
            .revoke_device(owner, device, now)
            .await
            .map_err(|e| KeyDirectoryError::Unexpected(e.into()))?;
        tell_ended(&*self.notifier, &ended);
        match self.devices.revoke(owner, device).await? {
            Revocation::Revoked | Revocation::AlreadyRevoked => Ok(()),
            Revocation::NotFound => Err(KeyDirectoryError::DeviceNotFound),
        }
    }
}
