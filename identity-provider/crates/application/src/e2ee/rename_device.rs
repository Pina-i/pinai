use std::sync::Arc;

use domain::DeviceId;
use domain::auth::Sessions;
use domain::e2ee::{ChosenName, Devices, KeyDirectoryError, Renaming};
use domain::identity::Bearer;

use crate::auth::calling_session;

/// `PUT /api/keys/devices/{id}/name`: the name the user gives one of their devices, or none for
/// its automatic one back — an approved device's only from a session whose device is approved
/// too, as a revoke. Nobody is told: the other devices see it when they read the list again.
pub struct RenameDevice {
    devices: Arc<dyn Devices>,
    sessions: Arc<dyn Sessions>,
}

impl RenameDevice {
    pub fn new(devices: Arc<dyn Devices>, sessions: Arc<dyn Sessions>) -> Self {
        Self { devices, sessions }
    }

    /// `DeviceNotFound` for a device that is not the owner's, so others' ids never leak.
    pub async fn execute(
        &self,
        bearer: &Bearer,
        device: DeviceId,
        name: Option<&ChosenName>,
    ) -> Result<(), KeyDirectoryError> {
        let by = calling_session(&*self.sessions, bearer)
            .await
            .map_err(|e| KeyDirectoryError::Unexpected(e.into()))?
            .device;
        match self.devices.rename(bearer.user, device, by, name).await? {
            Renaming::Renamed => Ok(()),
            Renaming::NotFound => Err(KeyDirectoryError::DeviceNotFound),
            Renaming::Revoked => Err(KeyDirectoryError::DeviceRevoked),
            Renaming::Refused(refusal) => Err(refusal.into()),
        }
    }
}
