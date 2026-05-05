//! Direct messaging domain: conversation management, message persistence,
//! reactions, replies, and outbound federation triggers. Inbound federated
//! DMs are persisted by `idp-federation::inbox` directly (a future revision
//! will move this dispatch through the broker per ADR-0001).

pub mod attachments;
pub mod blob;
pub mod handlers;
pub mod orphan_sweep;

pub use handlers::{
    add_reaction, edit_message, get_conversation, list_conversations, remove_reaction,
    send_message, AddReactionRequest, ConversationListItem, ConversationMemberInfo,
    ConversationQuery, EditMessageRequest, MessageResponse, ReactionGroup, RemoveReactionQuery,
    SendMessageRequest,
};
