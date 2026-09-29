use std::sync::Arc;

use domain::e2ee::{KeyDirectoryError, KeyPackagePolicy, KeyPackages};
use domain::{DeviceId, UserId};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceStash {
    pub device: DeviceId,
    pub available: usize,
    pub needs_refill: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StashStatus {
    pub devices: Vec<DeviceStash>,
    pub refill_threshold: usize,
    pub cap: usize,
}

/// `GET /api/keys/packages/status`: what each of the caller's devices has left.
pub struct KeyPackageStatus {
    policy: KeyPackagePolicy,
    key_packages: Arc<dyn KeyPackages>,
}

impl KeyPackageStatus {
    pub fn new(policy: KeyPackagePolicy, key_packages: Arc<dyn KeyPackages>) -> Self {
        Self {
            policy,
            key_packages,
        }
    }

    pub async fn execute(&self, owner: UserId) -> Result<StashStatus, KeyDirectoryError> {
        let devices = self
            .key_packages
            .available_per_device(owner)
            .await?
            .into_iter()
            .map(|(device, available)| DeviceStash {
                device,
                available,
                needs_refill: self.policy.needs_refill(available),
            })
            .collect();
        Ok(StashStatus {
            devices,
            refill_threshold: self.policy.refill_threshold,
            cap: self.policy.cap_per_device,
        })
    }
}
