use crate::identity::AccountsError;

use super::KeyPackageRefusal;

#[derive(Debug, thiserror::Error)]
pub enum KeyDirectoryError {
    #[error(transparent)]
    Refused(#[from] KeyPackageRefusal),
    #[error("device not found")]
    DeviceNotFound,
    #[error("the device is revoked")]
    DeviceRevoked,
    #[error("the device id is another account's")]
    DeviceTaken,
    #[error("user not found")]
    UserNotFound,
    #[error("no available KeyPackage")]
    NoKeyPackage,
    /// Peers ask the instance hosting the account, never through another one.
    #[error("peer-authenticated claim must target a local actor")]
    PeerMustTargetLocal,
    #[error("the peer's address is not allowed: {0}")]
    PeerNotAllowed(String),
    #[error("the account's instance is rate-limiting this one")]
    PeerBusy,
    #[error("the account's instance did not answer")]
    PeerUnavailable(#[source] anyhow::Error),
    #[error(transparent)]
    Unexpected(#[from] anyhow::Error),
}

/// What the device and KeyPackage stores fail with.
#[derive(Debug, thiserror::Error)]
pub enum KeyStoreError {
    #[error("the device id is another account's")]
    DeviceTaken,
    #[error(transparent)]
    Unexpected(#[from] anyhow::Error),
}

impl From<KeyStoreError> for KeyDirectoryError {
    fn from(error: KeyStoreError) -> Self {
        match error {
            KeyStoreError::DeviceTaken => Self::DeviceTaken,
            KeyStoreError::Unexpected(e) => Self::Unexpected(e),
        }
    }
}

impl From<AccountsError> for DeliveryError {
    fn from(error: AccountsError) -> Self {
        match error {
            AccountsError::Unexpected(e) => Self::Unexpected(e),
        }
    }
}

impl From<AccountsError> for KeyDirectoryError {
    fn from(error: AccountsError) -> Self {
        match error {
            AccountsError::Unexpected(e) => Self::Unexpected(e),
        }
    }
}

/// A claim another instance refused, or could not answer.
#[derive(Debug, thiserror::Error)]
pub enum RemoteClaimError {
    #[error("the peer's address is not allowed: {0}")]
    NotAllowed(String),
    #[error("no such account on its instance")]
    UserNotFound,
    #[error("the account has no KeyPackage left")]
    NoKeyPackage,
    #[error("the account's instance is rate-limiting this one")]
    Busy,
    #[error("the account's instance did not answer")]
    Unavailable(#[from] anyhow::Error),
}

impl From<RemoteClaimError> for KeyDirectoryError {
    fn from(error: RemoteClaimError) -> Self {
        match error {
            RemoteClaimError::NotAllowed(reason) => Self::PeerNotAllowed(reason),
            RemoteClaimError::UserNotFound => Self::UserNotFound,
            RemoteClaimError::NoKeyPackage => Self::NoKeyPackage,
            RemoteClaimError::Busy => Self::PeerBusy,
            RemoteClaimError::Unavailable(e) => Self::PeerUnavailable(e),
        }
    }
}

/// Why the Delivery Service refused a commit or a Welcome.
#[derive(Debug, thiserror::Error)]
pub enum DeliveryError {
    /// Also a conversation with no active member.
    #[error("conversation not found")]
    ConversationNotFound,
    #[error("not a member of this conversation")]
    NotAMember,
    #[error("the recipient is not a member of this conversation")]
    RecipientNotAMember,
    #[error("no such account here")]
    RecipientNotFound,
    /// Another commit holds the epoch: the proposer applies it and proposes again.
    #[error("another commit already exists at epoch {} for this conversation", .0.epoch.value())]
    EpochTaken(Box<super::Commit>),
    #[error(transparent)]
    Unexpected(#[from] anyhow::Error),
}

/// What the commit log and the Welcome queue fail with.
#[derive(Debug, thiserror::Error)]
pub enum DeliveryStoreError {
    #[error(transparent)]
    Unexpected(#[from] anyhow::Error),
}

impl From<DeliveryStoreError> for DeliveryError {
    fn from(error: DeliveryStoreError) -> Self {
        match error {
            DeliveryStoreError::Unexpected(e) => Self::Unexpected(e),
        }
    }
}

impl From<crate::messaging::MessageStoreError> for DeliveryError {
    fn from(error: crate::messaging::MessageStoreError) -> Self {
        Self::Unexpected(anyhow::Error::from(error))
    }
}

impl From<crate::identity::RemoteActorsError> for DeliveryError {
    fn from(error: crate::identity::RemoteActorsError) -> Self {
        Self::Unexpected(anyhow::Error::from(error))
    }
}

/// A roster only a member may assert: the messaging context refuses it as unknown.
impl From<crate::messaging::MessagingError> for DeliveryError {
    fn from(error: crate::messaging::MessagingError) -> Self {
        match error {
            crate::messaging::MessagingError::Unexpected(e) => Self::Unexpected(e),
            _ => Self::NotAMember,
        }
    }
}

/// Why the history archive refused an upload or a read.
#[derive(Debug, thiserror::Error)]
pub enum ArchiveError {
    #[error(transparent)]
    Refused(#[from] super::BatchSize),
    /// The archive holds only what its owner could read: conversations it is or was in.
    #[error("not a member of one or more conversations")]
    NotAMember,
    #[error("no salt set")]
    NoSalt,
    #[error(transparent)]
    Unexpected(#[from] anyhow::Error),
}

/// What the archive store fails with.
#[derive(Debug, thiserror::Error)]
pub enum ArchiveStoreError {
    #[error(transparent)]
    Unexpected(#[from] anyhow::Error),
}

impl From<ArchiveStoreError> for ArchiveError {
    fn from(error: ArchiveStoreError) -> Self {
        match error {
            ArchiveStoreError::Unexpected(e) => Self::Unexpected(e),
        }
    }
}

impl From<AccountsError> for ArchiveError {
    fn from(error: AccountsError) -> Self {
        match error {
            AccountsError::Unexpected(e) => Self::Unexpected(e),
        }
    }
}

impl From<crate::messaging::MessageStoreError> for ArchiveError {
    fn from(error: crate::messaging::MessageStoreError) -> Self {
        Self::Unexpected(anyhow::Error::from(error))
    }
}
