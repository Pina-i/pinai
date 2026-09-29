use std::sync::Arc;

use domain::e2ee::{CLAIMED_KEY_PACKAGE_GRACE, KeyDirectoryError, KeyPackages};
use time::OffsetDateTime;

/// Deletes KeyPackages expired, or claimed longer ago than the grace.
pub struct SweepKeyPackages {
    key_packages: Arc<dyn KeyPackages>,
}

impl SweepKeyPackages {
    pub fn new(key_packages: Arc<dyn KeyPackages>) -> Self {
        Self { key_packages }
    }

    /// How many were deleted.
    pub async fn execute(&self, now: OffsetDateTime) -> Result<usize, KeyDirectoryError> {
        Ok(self
            .key_packages
            .delete_spent(now, now - CLAIMED_KEY_PACKAGE_GRACE)
            .await?)
    }
}
