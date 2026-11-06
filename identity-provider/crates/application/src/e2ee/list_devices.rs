use std::sync::Arc;

use domain::UserId;
use domain::auth::{Sessions, last_active};
use domain::e2ee::{Approval, Device, DeviceApprovals, Devices, KeyDirectoryError};
use time::OffsetDateTime;

/// A device, whether it is signed in, and who approved it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedDevice {
    pub device: Device,
    /// Its live session's last use; `None` when it is signed out.
    pub last_active_at: Option<OffsetDateTime>,
    /// Oldest first.
    pub approvals: Vec<Approval>,
}

/// `GET /api/keys/devices`: the caller's devices, active first, each signed in or not, with their
/// approvals for the account's other devices to check.
pub struct ListDevices {
    devices: Arc<dyn Devices>,
    approvals: Arc<dyn DeviceApprovals>,
    sessions: Arc<dyn Sessions>,
}

impl ListDevices {
    pub fn new(
        devices: Arc<dyn Devices>,
        approvals: Arc<dyn DeviceApprovals>,
        sessions: Arc<dyn Sessions>,
    ) -> Self {
        Self {
            devices,
            approvals,
            sessions,
        }
    }

    pub async fn execute(
        &self,
        owner: UserId,
        now: OffsetDateTime,
    ) -> Result<Vec<ListedDevice>, KeyDirectoryError> {
        let devices = self.devices.list(owner).await?;
        let approvals = self.approvals.of_owner(owner).await?;
        let sessions = self
            .sessions
            .of_user(owner)
            .await
            .map_err(|e| KeyDirectoryError::Unexpected(e.into()))?;
        Ok(devices
            .into_iter()
            .map(|device| ListedDevice {
                last_active_at: last_active(&sessions, device.id, now),
                approvals: approvals
                    .iter()
                    .filter(|approval| binds(approval, &device))
                    .cloned()
                    .collect(),
                device,
            })
            .collect())
    }
}

/// Two reads may straddle a new root key: an approval of the one before is no longer one.
fn binds(approval: &Approval, device: &Device) -> bool {
    approval.device == device.id
        && device
            .attestation
            .as_ref()
            .is_some_and(|held| held.root_key == approval.root_key)
}
