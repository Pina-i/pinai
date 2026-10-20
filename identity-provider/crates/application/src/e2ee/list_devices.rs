use std::sync::Arc;

use domain::UserId;
use domain::auth::{Sessions, last_active};
use domain::e2ee::{Device, Devices, KeyDirectoryError};
use time::OffsetDateTime;

/// A device, and whether it is signed in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedDevice {
    pub device: Device,
    /// Its live session's last use; `None` when it is signed out.
    pub last_active_at: Option<OffsetDateTime>,
}

/// `GET /api/keys/devices`: the caller's devices, active first, each signed in or not.
pub struct ListDevices {
    devices: Arc<dyn Devices>,
    sessions: Arc<dyn Sessions>,
}

impl ListDevices {
    pub fn new(devices: Arc<dyn Devices>, sessions: Arc<dyn Sessions>) -> Self {
        Self { devices, sessions }
    }

    pub async fn execute(
        &self,
        owner: UserId,
        now: OffsetDateTime,
    ) -> Result<Vec<ListedDevice>, KeyDirectoryError> {
        let devices = self.devices.list(owner).await?;
        let sessions = self
            .sessions
            .of_user(owner)
            .await
            .map_err(|e| KeyDirectoryError::Unexpected(e.into()))?;
        Ok(devices
            .into_iter()
            .map(|device| ListedDevice {
                last_active_at: last_active(&sessions, device.id, now),
                device,
            })
            .collect())
    }
}
