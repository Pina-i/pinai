use std::sync::Arc;

use domain::DeviceId;
use domain::auth::{SessionNotifier, Sessions};
use domain::e2ee::{DeviceApprovals, DeviceTrustNotifier, Devices, KeyDirectoryError, Revocation};
use domain::identity::Bearer;
use time::OffsetDateTime;

use super::start_over::tell_start_over_ended;
use crate::auth::{calling_session, tell_ended};

/// `POST /api/keys/devices/{id}/revoke`: the device is flagged in the directory — an approved one
/// only from a session whose device is approved too —, the approval requests it took part in
/// closed and its start over request cancelled, then signed out — its sessions end, their tokens
/// and sockets with them, and for a web app's the browser session above it with that browser's
/// other apps, so no cookie signs it in again; the MLS Remove commits that exclude it are the
/// clients'. Revoking twice is fine, and finishes a revoke cut short.
pub struct RevokeDevice {
    devices: Arc<dyn Devices>,
    sessions: Arc<dyn Sessions>,
    approvals: Arc<dyn DeviceApprovals>,
    notifier: Arc<dyn SessionNotifier>,
    trust: Arc<dyn DeviceTrustNotifier>,
}

impl RevokeDevice {
    pub fn new(
        devices: Arc<dyn Devices>,
        sessions: Arc<dyn Sessions>,
        approvals: Arc<dyn DeviceApprovals>,
        notifier: Arc<dyn SessionNotifier>,
        trust: Arc<dyn DeviceTrustNotifier>,
    ) -> Self {
        Self {
            devices,
            sessions,
            approvals,
            notifier,
            trust,
        }
    }

    /// `DeviceNotFound` for a device that is not the owner's, so others' ids never leak.
    pub async fn execute(
        &self,
        bearer: &Bearer,
        device: DeviceId,
        now: OffsetDateTime,
    ) -> Result<(), KeyDirectoryError> {
        let owner = bearer.user;
        let by = calling_session(&*self.sessions, bearer)
            .await
            .map_err(|e| KeyDirectoryError::Unexpected(e.into()))?
            .device;
        let (closed, start_over) = match self.devices.revoke(owner, device, by, now).await? {
            Revocation::Revoked { closed, start_over } => (closed, start_over),
            // Its sessions are ended again: a revoke cut short before them finishes.
            Revocation::AlreadyRevoked => (Vec::new(), None),
            Revocation::NotFound => return Err(KeyDirectoryError::DeviceNotFound),
            Revocation::Refused(refusal) => return Err(refusal.into()),
        };
        // After the flag, which a link checks under the same row lock: nothing names it any more.
        let ended = self
            .sessions
            .revoke_device(owner, device, now)
            .await
            .map_err(|e| KeyDirectoryError::Unexpected(e.into()))?;
        tell_ended(&*self.notifier, &ended);
        // The revoke is done: what it closed is told as best it can be.
        if !closed.is_empty() {
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
        }
        if let Some(request) = start_over {
            match self.approvals.trust(owner).await {
                Ok(trust) => {
                    tell_start_over_ended(&*self.sessions, &*self.trust, &trust, &request, now)
                        .await;
                }
                Err(e) => {
                    tracing::warn!(error = ?e, user_id = %owner, "the cancelled start over went untold");
                }
            }
        }
        Ok(())
    }
}
