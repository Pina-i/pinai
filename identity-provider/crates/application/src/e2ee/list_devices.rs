use std::sync::Arc;

use domain::UserId;
use domain::e2ee::{Device, Devices, KeyDirectoryError};

/// `GET /api/keys/devices`: the caller's devices, active first.
pub struct ListDevices {
    devices: Arc<dyn Devices>,
}

impl ListDevices {
    pub fn new(devices: Arc<dyn Devices>) -> Self {
        Self { devices }
    }

    pub async fn execute(&self, owner: UserId) -> Result<Vec<Device>, KeyDirectoryError> {
        Ok(self.devices.list(owner).await?)
    }
}
