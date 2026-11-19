use std::sync::Arc;

use domain::DeviceId;
use domain::auth::Sessions;
use domain::e2ee::{
    BroughtLabel, Devices, KeyDirectoryError, KeyPackagePolicy, KeyPackages, NewKeyPackage,
};
use domain::identity::Bearer;
use time::OffsetDateTime;

use crate::auth::calling_session;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Uploaded {
    pub uploaded: usize,
    pub available_after: usize,
}

/// `POST /api/keys/packages`: a batch of one device's KeyPackages, refused whole or stored whole.
pub struct UploadKeyPackages {
    policy: KeyPackagePolicy,
    sessions: Arc<dyn Sessions>,
    devices: Arc<dyn Devices>,
    key_packages: Arc<dyn KeyPackages>,
}

impl UploadKeyPackages {
    pub fn new(
        policy: KeyPackagePolicy,
        sessions: Arc<dyn Sessions>,
        devices: Arc<dyn Devices>,
        key_packages: Arc<dyn KeyPackages>,
    ) -> Self {
        Self {
            policy,
            sessions,
            devices,
            key_packages,
        }
    }

    /// `label` names the device if this is the first the instance hears of it, else as
    /// [`BroughtLabel::write`] says.
    pub async fn execute(
        &self,
        bearer: &Bearer,
        device: DeviceId,
        label: BroughtLabel,
        packages: Vec<NewKeyPackage>,
        now: OffsetDateTime,
    ) -> Result<Uploaded, KeyDirectoryError> {
        let owner = bearer.user;
        let packages = self.policy.admit_batch(packages, now)?;
        let known = self.devices.find(device).await?;
        if let Some(known) = &known {
            known.usable_by(owner)?;
        }
        let session = calling_session(&*self.sessions, bearer)
            .await
            .map_err(|e| KeyDirectoryError::Unexpected(e.into()))?;
        let label = label.write(known.as_ref(), session.device);
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
