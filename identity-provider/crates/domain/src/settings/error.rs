use super::{SettingsDocument, SettingsStoreError};

#[derive(Debug, thiserror::Error)]
pub enum SettingsError {
    #[error(
        "the merged settings would exceed {} bytes",
        SettingsDocument::MAX_BYTES
    )]
    TooLarge,
    #[error(transparent)]
    Unexpected(#[from] anyhow::Error),
}

impl From<SettingsStoreError> for SettingsError {
    fn from(error: SettingsStoreError) -> Self {
        match error {
            SettingsStoreError::TooLarge => Self::TooLarge,
            SettingsStoreError::Unexpected(e) => Self::Unexpected(e),
        }
    }
}
