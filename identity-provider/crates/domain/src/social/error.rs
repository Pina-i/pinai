use crate::identity::{AccountsError, RemoteActorsError};

use super::{SocialStoreError, YouBlocked};

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
    #[error("the account's instance did not answer: {0}")]
    PeerUnavailable(String),
    #[error("a user cannot block themselves")]
    SelfBlock,
    #[error("the actor is not blocked")]
    NotBlocked,
    #[error("the block list is full")]
    BlockListFull,
    #[error("the caller blocked the target")]
    YouBlocked,
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
            RemoteActorsError::Unavailable(reason) => Self::PeerUnavailable(reason),
            RemoteActorsError::Unexpected(e) => Self::Unexpected(e),
        }
    }
}

impl From<YouBlocked> for SocialError {
    fn from(_: YouBlocked) -> Self {
        Self::YouBlocked
    }
}
