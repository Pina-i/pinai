use std::sync::Arc;

use domain::auth::{SessionNotifier, Sessions};
use domain::e2ee::{DeviceTrustNotifier, Devices, KeyDirectoryError, Revocation};
use domain::{DeviceId, UserId};
use time::OffsetDateTime;

use crate::auth::tell_ended;

/// `POST /api/keys/devices/{id}/revoke`: the device is flagged in the directory, the approval
/// requests it took part in closed, then signed out — its sessions end, their tokens and sockets
/// with them, and for a web app's the browser session above it with that browser's other apps,
/// so no cookie signs it in again; the MLS Remove commits that exclude it are the clients'.
/// Revoking twice is fine, and finishes a revoke cut short.
pub struct RevokeDevice {
    devices: Arc<dyn Devices>,
    sessions: Arc<dyn Sessions>,
    notifier: Arc<dyn SessionNotifier>,
    trust: Arc<dyn DeviceTrustNotifier>,
}

impl RevokeDevice {
    pub fn new(
        devices: Arc<dyn Devices>,
        sessions: Arc<dyn Sessions>,
        notifier: Arc<dyn SessionNotifier>,
        trust: Arc<dyn DeviceTrustNotifier>,
    ) -> Self {
        Self {
            devices,
            sessions,
            notifier,
            trust,
        }
    }

    /// `DeviceNotFound` for a device that is not the owner's, so others' ids never leak.
    pub async fn execute(
        &self,
        owner: UserId,
        device: DeviceId,
        now: OffsetDateTime,
    ) -> Result<(), KeyDirectoryError> {
        let closed = match self.devices.revoke(owner, device).await? {
            Revocation::Revoked { closed } => closed,
            // Its sessions are ended again: a revoke cut short before them finishes.
            Revocation::AlreadyRevoked => Vec::new(),
            Revocation::NotFound => return Err(KeyDirectoryError::DeviceNotFound),
        };
        // After the flag, which a link checks under the same row lock: nothing names it any more.
        let ended = self
            .sessions
            .revoke_device(owner, device, now)
            .await
            .map_err(|e| KeyDirectoryError::Unexpected(e.into()))?;
        tell_ended(&*self.notifier, &ended);
        if closed.is_empty() {
            return Ok(());
        }
        // The revoke is done: the other side's prompts are left to their expiry.
        match self.sessions.of_user(owner).await {
            Ok(sessions) => {
                for request in closed {
                    let to = request.parties().sessions(&sessions, now);
                    self.trust.approval_closed(owner, &to, request.id);
                }
            }
            Err(e) => {
                tracing::warn!(error = ?e, user_id = %owner, "the closed approval requests went untold");
            }
        }
        Ok(())
    }
}
