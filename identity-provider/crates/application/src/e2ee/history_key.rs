//! The account's history key: the generation its passphrase is at, which every device saves under
//! and says it holds.

use std::sync::Arc;

use domain::auth::Sessions;
use domain::e2ee::{
    ArchiveError, DeviceApprovals, DeviceTrustNotifier, Devices, HeldHistoryKey, HistoryGeneration,
    HistoryKey, HistoryKeys, Holding, KeyDirectoryError, KeyReplace, StaleHistoryKey,
    may_report_history_key, may_set_history_key,
};
use domain::identity::Bearer;
use domain::{DeviceId, UserId};
use time::OffsetDateTime;

use super::start_over::tell_start_over_ended;
use crate::auth::calling_session;

fn unexpected(error: impl Into<anyhow::Error>) -> ArchiveError {
    ArchiveError::Unexpected(error.into())
}

/// `GET /api/history/key`
pub struct LoadHistoryKey {
    keys: Arc<dyn HistoryKeys>,
}

impl LoadHistoryKey {
    pub fn new(keys: Arc<dyn HistoryKeys>) -> Self {
        Self { keys }
    }

    /// `NoKey` until a device sets the first.
    pub async fn execute(&self, owner: UserId) -> Result<HeldHistoryKey, ArchiveError> {
        self.keys.current(owner).await?.ok_or(ArchiveError::NoKey)
    }
}

/// `PUT /api/history/key`: the first device sets generation 1; a device approved under the
/// current one replaces it at once; any other through its matured start over request. Each later
/// generation erases the archive saved under the one before.
pub struct SetHistoryKey {
    sessions: Arc<dyn Sessions>,
    keys: Arc<dyn HistoryKeys>,
    approvals: Arc<dyn DeviceApprovals>,
    notifier: Arc<dyn DeviceTrustNotifier>,
}

impl SetHistoryKey {
    pub fn new(
        sessions: Arc<dyn Sessions>,
        keys: Arc<dyn HistoryKeys>,
        approvals: Arc<dyn DeviceApprovals>,
        notifier: Arc<dyn DeviceTrustNotifier>,
    ) -> Self {
        Self {
            sessions,
            keys,
            approvals,
            notifier,
        }
    }

    /// [`may_set_history_key`] here; the rest the store decides under the key's lock.
    pub async fn execute(
        &self,
        bearer: &Bearer,
        key: HistoryKey,
        now: OffsetDateTime,
    ) -> Result<(), ArchiveError> {
        let owner = bearer.user;
        let session = calling_session(&*self.sessions, bearer)
            .await
            .map_err(unexpected)?;
        let set_by = may_set_history_key(key.generation, bearer, session.device, now)?;
        // Read before the write drops the old generation's approvals: who to tell of a request it ends.
        let before = self.approvals.trust(owner).await.map_err(unexpected)?;
        match self.keys.replace(owner, &key, set_by, now).await? {
            KeyReplace::Replaced { erased, closed } => {
                let generation = key.generation.value();
                tracing::info!(user_id = %owner, set_by = %set_by, generation, erased, "history key replaced");
                for request in &closed {
                    tell_start_over_ended(&*self.sessions, &*self.notifier, &before, request, now)
                        .await;
                }
                Ok(())
            }
            KeyReplace::AlreadySet => Ok(()),
            KeyReplace::Conflict(current) => Err(ArchiveError::KeyConflict { current }),
            KeyReplace::Refused(refusal) => Err(refusal.into()),
        }
    }
}

/// `PUT /api/keys/devices/{device_id}/history-key`: a device says it holds the current history
/// key, so the account's other devices can tell which of them do.
pub struct ReportHistoryKey {
    sessions: Arc<dyn Sessions>,
    devices: Arc<dyn Devices>,
    keys: Arc<dyn HistoryKeys>,
}

impl ReportHistoryKey {
    pub fn new(
        sessions: Arc<dyn Sessions>,
        devices: Arc<dyn Devices>,
        keys: Arc<dyn HistoryKeys>,
    ) -> Self {
        Self {
            sessions,
            devices,
            keys,
        }
    }

    pub async fn execute(
        &self,
        bearer: &Bearer,
        device: DeviceId,
        generation: HistoryGeneration,
    ) -> Result<(), KeyDirectoryError> {
        let session = calling_session(&*self.sessions, bearer)
            .await
            .map_err(|e| KeyDirectoryError::Unexpected(e.into()))?;
        let found = self.devices.find(device).await?;
        let current = self
            .keys
            .current(bearer.user)
            .await
            .map_err(|e| KeyDirectoryError::Unexpected(e.into()))?
            .map(|held| held.key.generation);
        may_report_history_key(
            session.device,
            bearer.user,
            device,
            found.as_ref(),
            generation,
            current,
        )?;
        // What changed since the reads: a new generation, or the device revoked.
        match self
            .devices
            .hold_history_key(bearer.user, device, generation)
            .await?
        {
            Holding::Recorded => Ok(()),
            Holding::Stale => Err(StaleHistoryKey.into()),
            Holding::Refused => Err(KeyDirectoryError::DeviceRevoked),
        }
    }
}

#[cfg(test)]
mod tests;
