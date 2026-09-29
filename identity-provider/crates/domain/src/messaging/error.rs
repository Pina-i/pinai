use crate::identity::{AccountsError, RemoteActorsError};

#[derive(Debug, thiserror::Error)]
pub enum MessagingError {
    #[error("recipient not found")]
    RecipientNotFound,
    #[error("cannot send a DM to oneself")]
    SelfMessage,
    /// Also what a non-member is told, so a conversation's existence never leaks.
    #[error("conversation not found")]
    ConversationNotFound,
    #[error("parent message not found")]
    ParentNotFound,
    #[error("message not found, or not the caller's")]
    MessageNotFound,
    #[error("too many attachments (max {0} per message)")]
    TooManyAttachments(usize),
    #[error("an attachment is missing, linked to a delivered message, or not the sender's")]
    AttachmentsUnavailable,
    #[error("the peer's address is not allowed: {0}")]
    PeerNotAllowed(String),
    #[error("only a group's admins may do this")]
    NotAnAdmin,
    #[error("not a member of the group")]
    MemberNotFound,
    #[error("no such group")]
    GroupNotFound,
    #[error("a group needs at least one other member")]
    GroupNeedsMembers,
    #[error("the group's last admin cannot step down while others remain")]
    LastAdmin,
    #[error("already a member of the group")]
    AlreadyAMember,
    #[error(transparent)]
    Unexpected(#[from] anyhow::Error),
}

/// What the conversation and message stores fail with.
#[derive(Debug, thiserror::Error)]
pub enum MessageStoreError {
    #[error("an attachment is missing, linked to a delivered message, or not the sender's")]
    AttachmentsUnavailable,
    #[error(transparent)]
    Unexpected(#[from] anyhow::Error),
}

impl From<MessageStoreError> for MessagingError {
    fn from(error: MessageStoreError) -> Self {
        match error {
            MessageStoreError::AttachmentsUnavailable => Self::AttachmentsUnavailable,
            MessageStoreError::Unexpected(e) => Self::Unexpected(e),
        }
    }
}

impl From<AccountsError> for MessagingError {
    fn from(error: AccountsError) -> Self {
        match error {
            AccountsError::Unexpected(e) => Self::Unexpected(e),
        }
    }
}

impl From<RemoteActorsError> for MessagingError {
    fn from(error: RemoteActorsError) -> Self {
        match error {
            RemoteActorsError::NotFound => Self::RecipientNotFound,
            RemoteActorsError::Refused(reason) => Self::PeerNotAllowed(reason),
            RemoteActorsError::Unexpected(e) => Self::Unexpected(e),
        }
    }
}

/// What attachment use cases fail with. The texts are close to the API's; each adapter maps them.
#[derive(Debug, thiserror::Error)]
pub enum AttachmentError {
    #[error(transparent)]
    Refused(#[from] super::UploadRefusal),
    #[error("attachment not found")]
    NotFound,
    /// The message an attachment is linked to is gone.
    #[error("the attachment's message is missing")]
    MessageMissing,
    #[error("not authorised to access the attachment")]
    Forbidden,
    #[error("token expired")]
    TokenExpired,
    #[error("invalid token")]
    TokenInvalid,
    #[error("the token names another attachment")]
    TokenMismatch,
    #[error("the attachment is not hosted here")]
    NotHostedHere,
    #[error("the attachment is not linked to a message")]
    Unlinked,
    #[error("the requesting peer has no actor in this conversation")]
    PeerNotInConversation,
    #[error("the attachment id is already taken")]
    IdTaken,
    #[error(transparent)]
    Unexpected(#[from] anyhow::Error),
}

impl From<MessageStoreError> for AttachmentError {
    fn from(error: MessageStoreError) -> Self {
        match error {
            MessageStoreError::AttachmentsUnavailable => {
                Self::Unexpected(anyhow::anyhow!("attachments unavailable"))
            }
            MessageStoreError::Unexpected(e) => Self::Unexpected(e),
        }
    }
}

impl From<AccountsError> for AttachmentError {
    fn from(error: AccountsError) -> Self {
        match error {
            AccountsError::Unexpected(e) => Self::Unexpected(e),
        }
    }
}

/// An object store or a remote instance failed to hand over bytes.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct ObjectStoreError(#[from] pub anyhow::Error);

impl From<ObjectStoreError> for AttachmentError {
    fn from(error: ObjectStoreError) -> Self {
        Self::Unexpected(error.0)
    }
}
