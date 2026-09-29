use crate::identity::{AccountsError, RemoteActorsError};

use super::SocialStoreError;

#[derive(Debug, thiserror::Error)]
pub enum SocialError {
    #[error("no such user")]
    UserNotFound,
    #[error("a user cannot befriend themselves")]
    SelfRequest,
    #[error("already friends")]
    AlreadyFriends,
    #[error("not friends")]
    NotFriends,
    #[error("no such friend request")]
    RequestNotFound,
    #[error("the request belongs to another account")]
    NotYours,
    #[error("not an incoming friend request")]
    NotAnIncomingRequest,
    #[error("the peer is not allowed: {0}")]
    PeerNotAllowed(String),
    #[error(transparent)]
    Unexpected(#[from] anyhow::Error),
}

impl From<SocialStoreError> for SocialError {
    fn from(error: SocialStoreError) -> Self {
        match error {
            SocialStoreError::Conflict => Self::NotAnIncomingRequest,
            SocialStoreError::Unexpected(e) => Self::Unexpected(e),
        }
    }
}

impl From<AccountsError> for SocialError {
    fn from(error: AccountsError) -> Self {
        match error {
            AccountsError::Unexpected(e) => Self::Unexpected(e),
        }
    }
}

impl From<RemoteActorsError> for SocialError {
    fn from(error: RemoteActorsError) -> Self {
        match error {
            RemoteActorsError::NotFound => Self::UserNotFound,
            RemoteActorsError::Refused(reason) => Self::PeerNotAllowed(reason),
            RemoteActorsError::Unexpected(e) => Self::Unexpected(e),
        }
    }
}
