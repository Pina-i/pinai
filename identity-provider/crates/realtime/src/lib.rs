//! WebSocket realtime transport: connection registry (`WsHub`) and the typed
//! `WsEvent` / `WsClientMessage` envelopes exchanged with clients. This crate
//! is generic over domain logic — it knows nothing about messaging, presence,
//! or federation.

pub mod events;
pub mod hub;

pub use events::{
    DeviceJoinedPayload, DmDeliveryFailedPayload, DmPayload, EditedDmPayload, FriendshipPayload,
    GroupCreatedPayload, GroupRenamedPayload, HeartbeatAckPayload, MemberAddedPayload,
    MemberRemovedPayload, MemberRoleChangedPayload, MlsCommitPayload, MlsWelcomeReadyPayload,
    PresenceUpdatePayload, ProfileUpdatePayload, SendDmPayload, TypingPayload, TypingStartPayload,
    UnwatchConversationPayload, WatchConversationPayload, WsAttachment, WsClientMessage, WsEvent,
};
pub use hub::{ConnectionHandle, WsHub};
