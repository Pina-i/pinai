use crate::identity::AccountsError;
use crate::messaging::MessageStoreError;

#[derive(Debug, thiserror::Error)]
pub enum PresenceError {
    #[error("not a member of this conversation")]
    NotAMember,
    #[error(transparent)]
    Unexpected(#[from] anyhow::Error),
}

impl From<AccountsError> for PresenceError {
    fn from(error: AccountsError) -> Self {
        match error {
            AccountsError::Unexpected(e) => Self::Unexpected(e),
        }
    }
}

impl From<MessageStoreError> for PresenceError {
    fn from(error: MessageStoreError) -> Self {
        Self::Unexpected(anyhow::Error::from(error))
    }
}
