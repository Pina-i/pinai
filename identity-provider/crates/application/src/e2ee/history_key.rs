//! The account's history key: the generation its passphrase is at, which every device saves under
//! and says it holds.

use std::sync::Arc;

use domain::auth::Sessions;
use domain::e2ee::{
    ArchiveError, Devices, HeldHistoryKey, HistoryGeneration, HistoryKey, HistoryKeys, Holding,
    KeyDirectoryError, KeyReplace, StaleHistoryKey, may_report_history_key, may_set_history_key,
};
use domain::identity::Bearer;
use domain::{DeviceId, UserId};
use time::OffsetDateTime;

use crate::auth::calling_session;

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

/// `PUT /api/history/key`: the first device sets generation 1; a device that starts over sets the
/// next one, which erases the archive saved under the one before.
pub struct SetHistoryKey {
    sessions: Arc<dyn Sessions>,
    keys: Arc<dyn HistoryKeys>,
}

impl SetHistoryKey {
    pub fn new(sessions: Arc<dyn Sessions>, keys: Arc<dyn HistoryKeys>) -> Self {
        Self { sessions, keys }
    }

    /// `KeyConflict` with the current generation when `key`'s doesn't follow it.
    pub async fn execute(
        &self,
        bearer: &Bearer,
        key: HistoryKey,
        now: OffsetDateTime,
    ) -> Result<(), ArchiveError> {
        let session = calling_session(&*self.sessions, bearer)
            .await
            .map_err(|e| ArchiveError::Unexpected(e.into()))?;
        let set_by = may_set_history_key(key.generation, bearer, session.device, now)?;
        match self.keys.replace(bearer.user, &key, set_by).await? {
            KeyReplace::Replaced { erased } => {
                let generation = key.generation.value();
                tracing::info!(user_id = %bearer.user, generation, erased, "history key replaced");
                Ok(())
            }
            KeyReplace::AlreadySet => Ok(()),
            KeyReplace::Conflict(current) => Err(ArchiveError::KeyConflict { current }),
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
