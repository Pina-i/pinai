//! Conversations — DMs and groups — and the messages in them, whose bodies are opaque MLS
//! ciphertext.

mod attachment;
mod ciphertext;
mod conversation;
mod error;
mod event;
mod group;
mod group_change;
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
    Conversation, ConversationKind, ConversationSummary, Departure, GroupChanges, GroupSnapshot,
    Member, MemberView, Membership, Mirrored, Role, SnapshotMember, StampedName, may_hold_dm,
};
pub use error::{AttachmentError, MessageStoreError, MessagingError, ObjectStoreError};
pub use event::{EventWindow, GroupEvent, GroupEventKind, NamedEvent};
pub use group::{
    GroupName, MAX_MEMBERS, authorize_admin, has_room, initial_roster, may_stop_being_admin,
};
pub use group_change::{GroupChange, GroupChangeKind, GroupEffect};
pub use message::{DeliveryStatus, HistoryCursor, Message, NewMessage};
pub use ports::{
    Attachments, BlobTokenError, BlobTokens, Conversations, DeliveryFailed, DirectDelivery,
    GroupEvents, GroupFederation, GroupNotifier, MessageEvent, MessageFederation, MessageNotifier,
    Messages, ObjectStore, RemoteFiles,
};
