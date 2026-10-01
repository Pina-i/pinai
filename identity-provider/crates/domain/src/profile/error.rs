use crate::settings::SettingsStoreError;
use crate::social::SocialStoreError;

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

impl From<SocialStoreError> for ProfileError {
    fn from(error: SocialStoreError) -> Self {
        Self::Unexpected(error.into())
    }
}
