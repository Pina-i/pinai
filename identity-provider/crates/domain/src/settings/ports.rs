use crate::UserId;

use super::{SettingsDocument, SettingsPatch};

#[async_trait::async_trait]
pub trait SettingsStore: Send + Sync {
    /// The account's document, or `None` if it never saved any settings.
    async fn load(&self, user: UserId) -> Result<Option<SettingsDocument>, SettingsStoreError>;

    /// Replace the sections `patch` names, keep the others, and return the merged document.
    async fn merge(
        &self,
        user: UserId,
        patch: &SettingsPatch,
    ) -> Result<SettingsDocument, SettingsStoreError>;
}

/// Tells the account's live sessions that its settings changed.
pub trait SettingsNotifier: Send + Sync {
    fn settings_updated(&self, user: UserId, settings: &SettingsDocument);
}

#[derive(Debug, thiserror::Error)]
pub enum SettingsStoreError {
    #[error(
        "the merged settings would exceed {} bytes",
        SettingsDocument::MAX_BYTES
    )]
    TooLarge,
    #[error(transparent)]
    Unexpected(#[from] anyhow::Error),
}
