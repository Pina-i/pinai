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

    /// `label` names the device if this is the first the instance hears of it, or if it was
    /// recorded before its client said what it is ([`DeviceLabel::replaces`]).
    pub async fn execute(
        &self,
        owner: UserId,
        device: DeviceId,
        label: DeviceLabel,
        packages: Vec<NewKeyPackage>,
        now: OffsetDateTime,
    ) -> Result<Uploaded, KeyDirectoryError> {
        let packages = self.policy.admit_batch(packages, now)?;
        let known = self.devices.find(device).await?;
        if let Some(known) = &known {
            known.usable_by(owner)?;
        }
        let relabel = known.is_some_and(|known| label.replaces(&known.label));
        let available = self.key_packages.available(owner, device).await?;
        self.policy.check_stash(available, packages.len())?;
        let uploaded = self
            .key_packages
            .stash(owner, device, &label, relabel, &packages)
            .await?;
        Ok(Uploaded {
            uploaded,
            available_after: available + uploaded,
        })
    }
}
