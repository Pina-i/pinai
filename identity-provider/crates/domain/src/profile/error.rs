use crate::settings::SettingsStoreError;

#[derive(Debug, thiserror::Error)]
pub enum ProfileError {
    #[error("no such account")]
    UnknownUser,
    #[error("an actor may only update its own profile")]
    NotItsOwn,
    #[error(transparent)]
    Unexpected(#[from] anyhow::Error),
}

impl From<SettingsStoreError> for ProfileError {
    fn from(error: SettingsStoreError) -> Self {
        Self::Unexpected(error.into())
    }
}
