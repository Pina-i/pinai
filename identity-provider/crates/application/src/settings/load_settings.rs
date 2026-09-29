use std::sync::Arc;

use domain::UserId;
use domain::settings::{SettingsDocument, SettingsError, SettingsStore};

/// The account's settings document, `{}` when it never saved any — delivered on `/userinfo`.
pub struct LoadSettings {
    store: Arc<dyn SettingsStore>,
}

impl LoadSettings {
    pub fn new(store: Arc<dyn SettingsStore>) -> Self {
        Self { store }
    }

    pub async fn execute(&self, user: UserId) -> Result<SettingsDocument, SettingsError> {
        let stored = self.store.load(user).await?;
        Ok(stored.unwrap_or_else(SettingsDocument::empty))
    }
}
