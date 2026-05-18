//! Direct messaging domain: conversation management, message persistence
//! (opaque MLS ciphertext), replies, and outbound federation triggers.
//! Inbound federated DMs are persisted by `idp-federation::mls` (the
//! application-message branch of `handle_inbound_mls_note`).
//!
//! Reactions left this crate in Phase 3 — they're now MLS application
//! messages of `kind = "reaction"`, indistinguishable from text on the wire.

pub mod attachments;
pub mod blob;
pub mod handlers;
pub mod orphan_sweep;

pub use handlers::{
    edit_message, get_conversation, list_conversations, mark_read, send_message,
    ConversationListItem, ConversationMemberInfo, ConversationQuery, EditMessageRequest,
    MessageResponse, SendMessageRequest,
};
