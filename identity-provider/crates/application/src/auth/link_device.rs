use std::sync::Arc;

use domain::DeviceId;
use domain::auth::{AuthError, SessionNotifier, Sessions};
use domain::e2ee::Devices;
use domain::identity::Bearer;
use time::OffsetDateTime;

use super::tell_ended;

/// `PUT /api/sessions/current/device`: the client names the E2EE device its session signed in,
/// once that device's storage is open, so revoking the device signs it out. A device is signed
/// in once at a time: a session it held before ends.
pub struct LinkDevice {
    devices: Arc<dyn Devices>,
    sessions: Arc<dyn Sessions>,
    notifier: Arc<dyn SessionNotifier>,
}

impl LinkDevice {
    pub fn new(
        devices: Arc<dyn Devices>,
        sessions: Arc<dyn Sessions>,
        notifier: Arc<dyn SessionNotifier>,
    ) -> Self {
        Self {
            devices,
            sessions,
            notifier,
        }
    }

    /// `DeviceRefused` for a device that isn't the account's, or is revoked.
    pub async fn execute(
        &self,
        bearer: Bearer,
        device: DeviceId,
        now: OffsetDateTime,
    ) -> Result<(), AuthError> {
        let usable = self
            .devices
            .find(device)
            .await
            .map_err(|e| AuthError::Unexpected(e.into()))?
            .is_some_and(|found| found.usable_by(bearer.user).is_ok());
        if !usable {
            return Err(AuthError::DeviceRefused);
        }
        let replaced = self.sessions.link(bearer.session, device, now).await?;
        tell_ended(&*self.notifier, &replaced);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
