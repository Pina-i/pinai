//! Conversations — DMs and groups — and the messages in them, whose bodies are opaque MLS
//! ciphertext.

mod attachment;
mod ciphertext;
mod conversation;
mod error;
mod group;
mod message;
mod ports;
#[cfg(any(test, feature = "test-utils"))]
pub mod testing;

pub use attachment::{
    Attachment, AttachmentLimits, AttachmentView, ByteStream, OfferedAttachment, RemoteAttachment,
    UploadFile, UploadRefusal, peer_may_fetch,
};
pub use ciphertext::MlsCiphertext;
pub use conversation::{
    Conversation, ConversationKind, ConversationSummary, GroupSnapshot, Member, MemberView, Role,
    may_hold_dm,
};
pub use error::{AttachmentError, MessageStoreError, MessagingError, ObjectStoreError};
pub use group::{GroupName, authorize_admin, initial_roster, may_stop_being_admin};
pub use message::{DeliveryStatus, HistoryCursor, Message, NewMessage};
pub use ports::{
    Attachments, BlobTokenError, BlobTokens, Conversations, DeliveryFailed, DirectDelivery,
    GroupNotifier, MessageEvent, MessageFederation, MessageNotifier, Messages, ObjectStore,
    RemoteFiles,
};
