use std::sync::Arc;

use domain::e2ee::{CLAIMED_WELCOME_GRACE, DeliveryError, Welcomes};
use time::OffsetDateTime;

/// Deletes Welcomes claimed longer ago than the grace.
pub struct SweepWelcomes {
    welcomes: Arc<dyn Welcomes>,
}

impl SweepWelcomes {
    pub fn new(welcomes: Arc<dyn Welcomes>) -> Self {
        Self { welcomes }
    }

    /// How many were deleted.
    pub async fn execute(&self, now: OffsetDateTime) -> Result<usize, DeliveryError> {
        Ok(self
            .welcomes
            .delete_claimed_before(now - CLAIMED_WELCOME_GRACE)
            .await?)
    }
}
