use std::sync::Arc;

use domain::e2ee::{
    DeviceLabel, Devices, KeyDirectoryError, KeyPackagePolicy, KeyPackages, NewKeyPackage,
};
use domain::{DeviceId, UserId};
use time::OffsetDateTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Uploaded {
    pub uploaded: usize,
    pub available_after: usize,
}

/// `POST /api/keys/packages`: a batch of one device's KeyPackages, refused whole or stored whole.
pub struct UploadKeyPackages {
    policy: KeyPackagePolicy,
    devices: Arc<dyn Devices>,
    key_packages: Arc<dyn KeyPackages>,
}

impl UploadKeyPackages {
    pub fn new(
        policy: KeyPackagePolicy,
        devices: Arc<dyn Devices>,
        key_packages: Arc<dyn KeyPackages>,
    ) -> Self {
        Self {
            policy,
            devices,
            key_packages,
        }
    }

    /// `label` names the device if this is the first the instance hears of it.
    pub async fn execute(
        &self,
        owner: UserId,
        device: DeviceId,
        label: DeviceLabel,
        packages: Vec<NewKeyPackage>,
        now: OffsetDateTime,
    ) -> Result<Uploaded, KeyDirectoryError> {
        self.policy.check_batch(&packages, now)?;
        if let Some(known) = self.devices.find(device).await? {
            known.usable_by(owner)?;
        }
        let available = self.key_packages.available(owner, device).await?;
        self.policy.check_stash(available, packages.len())?;
        let uploaded = self
            .key_packages
            .stash(owner, device, &label, &packages)
            .await?;
        Ok(Uploaded {
            uploaded,
            available_after: available + uploaded,
        })
    }
}
