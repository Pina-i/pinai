use std::sync::Arc;

use domain::e2ee::{Devices, KeyDirectoryError, Revocation};
use domain::{DeviceId, UserId};

/// `POST /api/keys/devices/{id}/revoke`: the directory's flag; the MLS Remove commits that
/// exclude the device are the clients'. Revoking twice is fine.
pub struct RevokeDevice {
    devices: Arc<dyn Devices>,
}

impl RevokeDevice {
    pub fn new(devices: Arc<dyn Devices>) -> Self {
        Self { devices }
    }

    /// `DeviceNotFound` for a device that is not the owner's, so others' ids never leak.
    pub async fn execute(&self, owner: UserId, device: DeviceId) -> Result<(), KeyDirectoryError> {
        match self.devices.revoke(owner, device).await? {
            Revocation::Revoked | Revocation::AlreadyRevoked => Ok(()),
            Revocation::NotFound => Err(KeyDirectoryError::DeviceNotFound),
        }
    }
}
