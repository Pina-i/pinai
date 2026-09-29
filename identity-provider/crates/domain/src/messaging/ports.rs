use time::OffsetDateTime;

use crate::identity::{Account, ActorUri, RemoteActor};
use crate::{AttachmentId, ConversationId, MessageId, UserId};

use super::{
    Attachment, ByteStream, Conversation, ConversationKind, ConversationSummary, DeliveryStatus,
    GroupName, GroupSnapshot, HistoryCursor, Member, Message, MessageStoreError, MlsCiphertext,
    NewMessage, ObjectStoreError, RemoteAttachment, Role,
};

/// Conversations and who is in them.
#[async_trait::async_trait]
pub trait Conversations: Send + Sync {
    /// The DM the two share, opened when there is none. `pinned` is the id a client or a peer
    /// chose for it (the MLS group id it already bootstrapped).
    async fn open_dm(
        &self,
        a: &ActorUri,
        b: &ActorUri,
        pinned: Option<ConversationId>,
    ) -> Result<ConversationId, MessageStoreError>;

    async fn find(&self, id: ConversationId) -> Result<Option<Conversation>, MessageStoreError>;

    /// The active members, in their roles.
    async fn members(&self, id: ConversationId) -> Result<Vec<Member>, MessageStoreError>;

    /// The conversations among `ids` that `actor` is, or once was, a member of.
    async fn ever_held(
        &self,
        actor: &ActorUri,
        ids: &[ConversationId],
    ) -> Result<Vec<ConversationId>, MessageStoreError>;

    /// Mirror a group another instance advertised: create it when new, take its name, and hold
    /// every member of the snapshot in its role.
    async fn mirror_group(
        &self,
        id: ConversationId,
        snapshot: &GroupSnapshot,
    ) -> Result<Conversation, MessageStoreError>;

    /// The account's conversations, the most recently active first.
    async fn list_for(
        &self,
        user: UserId,
        actor: &ActorUri,
    ) -> Result<Vec<ConversationSummary>, MessageStoreError>;

    async fn mark_read(&self, user: UserId, id: ConversationId) -> Result<(), MessageStoreError>;

    /// A new group with its whole roster, in one step.
    async fn create_group(
        &self,
        name: Option<&GroupName>,
        roster: &[Member],
    ) -> Result<Conversation, MessageStoreError>;

    /// Hold `member` in the conversation in its role: joining, rejoining after leaving, or
    /// taking that role.
    async fn add_member(
        &self,
        id: ConversationId,
        member: &Member,
    ) -> Result<(), MessageStoreError>;

    /// `false` when `actor` was not an active member.
    async fn remove_member(
        &self,
        id: ConversationId,
        actor: &ActorUri,
    ) -> Result<bool, MessageStoreError>;

    /// `None` when `actor` is not an active member.
    async fn set_role(
        &self,
        id: ConversationId,
        actor: &ActorUri,
        role: Role,
    ) -> Result<Option<Member>, MessageStoreError>;

    /// `None` when `id` names no group.
    async fn rename_group(
        &self,
        id: ConversationId,
        name: &GroupName,
    ) -> Result<Option<Conversation>, MessageStoreError>;
}

/// The messages of every conversation.
#[async_trait::async_trait]
pub trait Messages: Send + Sync {
    /// Store a message sent from this instance and link its attachments, in one step:
    /// `AttachmentsUnavailable` stores nothing.
    async fn record(&self, message: &NewMessage) -> Result<Message, MessageStoreError>;

    /// Store a message another instance delivered, with the attachments it describes. `None`
    /// when it is already stored: deliveries are at least once.
    async fn record_received(
        &self,
        message: &NewMessage,
        attachments: &[RemoteAttachment],
    ) -> Result<Option<Message>, MessageStoreError>;

    async fn find(&self, id: MessageId) -> Result<Option<Message>, MessageStoreError>;

    async fn find_by_activity(&self, uri: &str) -> Result<Option<Message>, MessageStoreError>;

    /// Replace the ciphertext of a message `sender` sent and did not delete, stamping
    /// `edited_at`. `None` when there is no such message.
    async fn edit(
        &self,
        id: MessageId,
        sender: &ActorUri,
        ciphertext: &MlsCiphertext,
    ) -> Result<Option<Message>, MessageStoreError>;

    /// The same, for the message an activity published.
    async fn edit_by_activity(
        &self,
        uri: &str,
        sender: &ActorUri,
        ciphertext: &MlsCiphertext,
    ) -> Result<Option<Message>, MessageStoreError>;

    /// A page of a conversation, newest first, before `cursor`; deleted messages left out.
    async fn history(
        &self,
        conversation: ConversationId,
        before: Option<HistoryCursor>,
        limit: i64,
    ) -> Result<Vec<Message>, MessageStoreError>;

    async fn set_delivery(
        &self,
        id: MessageId,
        status: DeliveryStatus,
    ) -> Result<(), MessageStoreError>;

    /// Mark `failed` each message sent from this instance to another before `sent_before`
    /// whose delivery never ended — its outcome was lost with the process that delivered it —
    /// and return them. Local and group messages keep `pending`: they are never delivered.
    async fn fail_stale_deliveries(
        &self,
        sent_before: OffsetDateTime,
    ) -> Result<Vec<Message>, MessageStoreError>;
}

/// What a member's clients are told about a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageEvent {
    pub message: Message,
    pub kind: ConversationKind,
    pub sender_address: String,
    pub sender_display_name: Option<String>,
    /// The sender's correlation token, on the sender's own copy only.
    pub client_id: Option<String>,
}

/// Tells local accounts' clients about messages.
pub trait MessageNotifier: Send + Sync {
    /// On the account's live sessions and in its event stream.
    fn message(&self, to: UserId, event: &MessageEvent);
    /// The sender's own copy, on its live sessions only.
    fn echo(&self, to: UserId, event: &MessageEvent);
    /// A new ciphertext for a message, on the live sessions and in the event stream.
    fn edited(&self, to: UserId, message: &Message);
    /// The editor's own copy of an edit, on its live sessions only.
    fn edit_echoed(&self, to: UserId, message: &Message);
    /// A message to another instance could not be delivered.
    fn delivery_failed(&self, to: UserId, message: &Message);
}

/// Tells local accounts' live sessions what happened to the groups they are in. Members on other
/// instances learn it from the MLS commits and the rosters that messages carry.
pub trait GroupNotifier: Send + Sync {
    /// The account is now a member of a group: created here, or mirrored from another instance.
    fn joined(&self, to: UserId, group: &Conversation, creator: &ActorUri);
    fn member_added(&self, to: UserId, group: ConversationId, member: &Member, by: &ActorUri);
    /// `by` is `None` when the member left on their own.
    fn member_removed(
        &self,
        to: UserId,
        group: ConversationId,
        member: &ActorUri,
        by: Option<&ActorUri>,
    );
    fn renamed(&self, to: UserId, group: &Conversation, by: &ActorUri);
    fn role_changed(&self, to: UserId, group: ConversationId, member: &Member, by: &ActorUri);
}

/// A 1:1 message on its way to the recipient's instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectDelivery {
    pub from: Account,
    pub to: RemoteActor,
    pub message: Message,
    /// The activity URI of the message it answers.
    pub reply_to: Option<String>,
}

#[derive(Debug, thiserror::Error)]
#[error("delivery failed: {0}")]
pub struct DeliveryFailed(pub String);

/// Messages sent to other instances.
#[async_trait::async_trait]
pub trait MessageFederation: Send + Sync {
    /// Deliver a 1:1 message. Awaited, so that its outcome can be recorded on the message.
    async fn deliver_direct(&self, delivery: &DirectDelivery) -> Result<(), DeliveryFailed>;

    /// Fan a group message out to its remote members, each copy carrying the roster.
    /// Fire-and-forget: a group message has no delivery status.
    fn send_to_group(
        &self,
        from: &Account,
        to: &[RemoteActor],
        message: &Message,
        reply_to: Option<&str>,
        group: &GroupSnapshot,
    );

    /// A message's new ciphertext. Fire-and-forget.
    fn send_edit(&self, from: &Account, to: &RemoteActor, message: &Message);
}

/// Attachments' records: uploads here, and those recorded for delivered messages.
#[async_trait::async_trait]
pub trait Attachments: Send + Sync {
    async fn find(&self, id: AttachmentId) -> Result<Option<Attachment>, MessageStoreError>;

    /// Record an upload, unlinked. `false` when the id is already taken.
    async fn record_upload(&self, upload: &Attachment) -> Result<bool, MessageStoreError>;

    async fn delete(&self, id: AttachmentId) -> Result<(), MessageStoreError>;

    /// Uploads still unlinked that were recorded before `cutoff`.
    async fn orphans_older_than(
        &self,
        cutoff: OffsetDateTime,
    ) -> Result<Vec<Attachment>, MessageStoreError>;
}

/// The bytes of attachments uploaded here. It stays on the private network: every byte a
/// browser or a peer sees goes through this instance.
#[async_trait::async_trait]
pub trait ObjectStore: Send + Sync {
    async fn put(
        &self,
        id: AttachmentId,
        bytes: Vec<u8>,
        mime_type: &str,
    ) -> Result<(), ObjectStoreError>;

    async fn get(&self, id: AttachmentId) -> Result<ByteStream, ObjectStoreError>;

    /// Nothing to delete is no error.
    async fn delete(&self, id: AttachmentId) -> Result<(), ObjectStoreError>;
}

/// The bytes of an attachment another instance hosts, fetched as this instance.
#[async_trait::async_trait]
pub trait RemoteFiles: Send + Sync {
    async fn fetch(&self, url: &str) -> Result<ByteStream, ObjectStoreError>;
}

/// Short-lived capabilities to one attachment's bytes, for a browser that cannot send a bearer
/// token with an `<img>`.
pub trait BlobTokens: Send + Sync {
    /// A token for `user` to read `attachment`, and when it expires.
    fn mint(&self, user: UserId, attachment: AttachmentId) -> (String, OffsetDateTime);

    fn verify(&self, token: &str) -> Result<(UserId, AttachmentId), BlobTokenError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BlobTokenError {
    #[error("token expired")]
    Expired,
    #[error("invalid token")]
    Invalid,
}
