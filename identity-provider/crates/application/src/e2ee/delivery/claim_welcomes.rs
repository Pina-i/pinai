use std::sync::Arc;

use domain::e2ee::{DeliveryError, Welcome, Welcomes};
use domain::{DeviceId, UserId};

/// `GET /api/mls/welcomes?device_id=`: the Welcomes waiting for one of the caller's devices —
/// per device, so a sibling never takes another's.
pub struct ClaimWelcomes {
    welcomes: Arc<dyn Welcomes>,
}

impl ClaimWelcomes {
    pub fn new(welcomes: Arc<dyn Welcomes>) -> Self {
        Self { welcomes }
    }

    pub async fn execute(
        &self,
        caller: UserId,
        device: DeviceId,
    ) -> Result<Vec<Welcome>, DeliveryError> {
        Ok(self.welcomes.claim(caller, device).await?)
    }
}
