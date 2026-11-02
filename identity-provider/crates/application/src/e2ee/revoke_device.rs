use std::sync::Arc;

use domain::auth::{SessionNotifier, Sessions};
use domain::e2ee::{ApprovalNotifier, Devices, KeyDirectoryError, Revocation};
use domain::{DeviceId, UserId};
use time::OffsetDateTime;

use crate::auth::tell_ended;

/// `POST /api/keys/devices/{id}/revoke`: the device is signed out — its sessions end, their
/// tokens and sockets with them — and flagged in the directory, the approval requests it took part
/// in closed; the MLS Remove commits that exclude it are the clients'. Revoking twice is fine.
pub struct RevokeDevice {
    devices: Arc<dyn Devices>,
    sessions: Arc<dyn Sessions>,
    notifier: Arc<dyn SessionNotifier>,
    approvals: Arc<dyn ApprovalNotifier>,
}

impl RevokeDevice {
    pub fn new(
        devices: Arc<dyn Devices>,
        sessions: Arc<dyn Sessions>,
        notifier: Arc<dyn SessionNotifier>,
        approvals: Arc<dyn ApprovalNotifier>,
    ) -> Self {
        Self {
            devices,
            sessions,
            notifier,
            approvals,
        }
    }

    /// `DeviceNotFound` for a device that is not the owner's, so others' ids never leak.
    pub async fn execute(
        &self,
        owner: UserId,
        device: DeviceId,
        now: OffsetDateTime,
    ) -> Result<(), KeyDirectoryError> {
        // Signed out before the flag: should the flag fail, the device is out all the same,
        // and revoking again finishes.
        let ended = self
            .sessions
            .revoke_device(owner, device, now)
            .await
            .map_err(|e| KeyDirectoryError::Unexpected(e.into()))?;
        tell_ended(&*self.notifier, &ended);
        let closed = match self.devices.revoke(owner, device).await? {
            Revocation::Revoked { closed } => closed,
            Revocation::AlreadyRevoked => return Ok(()),
            Revocation::NotFound => return Err(KeyDirectoryError::DeviceNotFound),
        };
        if closed.is_empty() {
            return Ok(());
        }
        // The revoke is done: the other side's prompts are left to their expiry.
        match self.sessions.of_user(owner).await {
            Ok(sessions) => {
                for request in closed {
                    let to = request.parties().sessions(&sessions, now);
                    self.approvals.approval_closed(owner, &to, request.id);
                }
            }
            Err(e) => {
                tracing::warn!(error = ?e, user_id = %owner, "the closed approval requests went untold");
            }
        }
        Ok(())
    }
}
