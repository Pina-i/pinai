use std::sync::Arc;

use domain::DeviceId;
use domain::auth::{AuthError, SessionNotifier, Sessions, may_name_device};
use domain::e2ee::{Devices, Ed25519Signature, Ed25519Verifier};
use domain::identity::{Accounts, Bearer};
use time::OffsetDateTime;

use super::tell_ended;

/// `PUT /api/sessions/current/device`: the client names the E2EE device its session signed in,
/// proving it holds that device's root key, so revoking the device signs it out. A device is
/// signed in once at a time: a session it held before ends. A session names one device, for good.
pub struct LinkDevice {
    accounts: Arc<dyn Accounts>,
    devices: Arc<dyn Devices>,
    verifier: Arc<dyn Ed25519Verifier>,
    sessions: Arc<dyn Sessions>,
    notifier: Arc<dyn SessionNotifier>,
}

impl LinkDevice {
    pub fn new(
        accounts: Arc<dyn Accounts>,
        devices: Arc<dyn Devices>,
        verifier: Arc<dyn Ed25519Verifier>,
        sessions: Arc<dyn Sessions>,
        notifier: Arc<dyn SessionNotifier>,
    ) -> Self {
        Self {
            accounts,
            devices,
            verifier,
            sessions,
            notifier,
        }
    }

    /// What `domain::auth::may_name_device` refuses — `DeviceRefused`, `DeviceProofInvalid` —, then
    /// what `may_link` refuses: `DeviceMismatch` for a session that named another, `SessionEnded`
    /// for one over since its token was checked.
    pub async fn execute(
        &self,
        bearer: Bearer,
        device: DeviceId,
        proof: Option<Ed25519Signature>,
        now: OffsetDateTime,
    ) -> Result<(), AuthError> {
        let found = self
            .devices
            .find(device)
            .await
            .map_err(|e| AuthError::Unexpected(e.into()))?;
        let account = self
            .accounts
            .find(bearer.user)
            .await
            .map_err(|e| AuthError::Unexpected(e.into()))?
            .ok_or(AuthError::UnknownUser)?;
        may_name_device(
            bearer.user,
            found.as_ref(),
            &account.actor_uri,
            bearer.session,
            proof.as_ref(),
            &*self.verifier,
        )?;
        let replaced = self
            .sessions
            .link(bearer.user, bearer.session, device, now)
            .await?;
        tell_ended(&*self.notifier, &replaced);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
