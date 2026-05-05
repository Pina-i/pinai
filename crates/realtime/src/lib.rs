//! WebSocket realtime transport: connection registry (`WsHub`) and the typed
//! `WsEvent` / `WsClientMessage` envelopes exchanged with clients. This crate
//! is generic over domain logic — it knows nothing about messaging, presence,
//! or federation.

pub mod events;
pub mod hub;

pub use events::{
    DmPayload, EditedDmPayload, FriendshipPayload, HeartbeatAckPayload, PresenceUpdatePayload,
    ProfileUpdatePayload, ReactionPayload, SendDmPayload, TypingPayload, TypingStartPayload,
    UnwatchConversationPayload, WatchConversationPayload, WsClientMessage, WsEvent,
};
pub use hub::{ConnectionHandle, WsHub};
