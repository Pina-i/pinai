use std::sync::Arc;

use domain::UserId;
use domain::settings::{
    SettingsDocument, SettingsError, SettingsNotifier, SettingsPatch, SettingsStore,
};

/// `PATCH /api/settings`: merge a change into the account's settings, then tell its sessions.
pub struct UpdateSettings {
    store: Arc<dyn SettingsStore>,
    notifier: Arc<dyn SettingsNotifier>,
}

impl UpdateSettings {
    pub fn new(store: Arc<dyn SettingsStore>, notifier: Arc<dyn SettingsNotifier>) -> Self {
        Self { store, notifier }
    }

    pub async fn execute(
        &self,
        user: UserId,
        patch: SettingsPatch,
    ) -> Result<SettingsDocument, SettingsError> {
        let merged = self.store.merge(user, &patch).await?;
        self.notifier.settings_updated(user, &merged);
        Ok(merged)
    }
}

#[cfg(test)]
mod tests;
