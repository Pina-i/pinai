use crate::identity::{AccountsError, ActorUri, RemoteActorsError};
use crate::social::{SocialStoreError, Unreachable, YouBlocked};

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
    #[error("the account's instance did not answer: {0}")]
    PeerUnavailable(String),
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
    #[error("a group holds at most {0} members")]
    TooManyMembers(usize),
    #[error("the group is full: it holds at most {0} members")]
    GroupFull(usize),
    #[error("only a group one was removed from can be cleared from one's list")]
    StillAMember,
    #[error("the sender blocked the recipient")]
    YouBlocked,
    /// A local invitee who doesn't admit the adder, whatever the cause.
    #[error("the invitee cannot be added")]
    CannotAdd(ActorUri),
    #[error("the adder blocked the invitee")]
    YouBlockedInvitee(ActorUri),
    /// Neither this instance nor the invitee's knows an account by that URI.
    #[error("no such account")]
    InviteeNotFound(ActorUri),
    #[error("the invitee's instance did not answer")]
    InviteeUnavailable(ActorUri),
    /// A block or the recipient's contact setting, which nobody outside their instance may tell
    /// apart.
    #[error("the recipient cannot be reached")]
    Undeliverable,
    #[error(transparent)]
    Unexpected(#[from] anyhow::Error),
}

impl From<Unreachable> for MessagingError {
    fn from(_: Unreachable) -> Self {
        Self::Undeliverable
    }
}

impl From<YouBlocked> for MessagingError {
    fn from(_: YouBlocked) -> Self {
        Self::YouBlocked
    }
}

impl From<SocialStoreError> for MessagingError {
    fn from(error: SocialStoreError) -> Self {
        Self::Unexpected(error.into())
    }
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
            RemoteActorsError::Unavailable(reason) => Self::PeerUnavailable(reason),
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
