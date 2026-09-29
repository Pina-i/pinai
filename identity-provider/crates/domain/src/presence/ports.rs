use std::collections::HashMap;

use futures_core::stream::BoxStream;

use crate::identity::{ActorUri, Domain};
use crate::{ConversationId, UserId};

use super::{PresenceError, PresenceEvent, PresenceState, Signal, TypingEvent};

/// The instance's presence bus: what one connection's worker publishes, every worker hears.
#[async_trait::async_trait]
pub trait SignalBus: Send + Sync {
    async fn publish(&self, signal: &Signal) -> Result<(), PresenceError>;
}

/// Everything on the bus from now on, for one listener — a peer's stream.
#[async_trait::async_trait]
pub trait SignalFeed: Send + Sync {
    async fn subscribe(&self) -> Result<BoxStream<'static, Signal>, PresenceError>;
}

/// The presence other instances hold for their accounts, asked as this instance.
#[async_trait::async_trait]
pub trait PeerPresence: Send + Sync {
    async fn poll(
        &self,
        peer: &Domain,
        actors: &[ActorUri],
    ) -> Result<Vec<(ActorUri, PresenceState)>, PresenceError>;
}

/// Pushes presence and typing to an account's live sessions.
pub trait PresenceNotifier: Send + Sync {
    fn presence(&self, to: UserId, event: &PresenceEvent);
    fn typing(&self, to: UserId, event: &TypingEvent);
}

/// Who hears of whom.
#[async_trait::async_trait]
pub trait PresenceAudience: Send + Sync {
    /// The local accounts that count `actor` among their friends.
    async fn befriended_by(&self, actor: &ActorUri) -> Result<Vec<UserId>, PresenceError>;
    /// The actors among `among` that `viewer` counts among its friends or shares an active
    /// conversation with.
    async fn known_to(
        &self,
        viewer: UserId,
        viewer_actor: &ActorUri,
        among: &[ActorUri],
    ) -> Result<Vec<ActorUri>, PresenceError>;
    /// Every actor some local account counts among its friends.
    async fn befriended(&self) -> Result<Vec<ActorUri>, PresenceError>;
    /// The actors among `among` that an account on `peer` shares an active conversation with,
    /// or is the friend of — a local account.
    async fn known_on(
        &self,
        peer: &Domain,
        among: &[ActorUri],
    ) -> Result<Vec<ActorUri>, PresenceError>;
    /// The conversations any of `among` is in together with an account on `peer`, both active.
    async fn conversations_with(
        &self,
        peer: &Domain,
        among: &[ActorUri],
    ) -> Result<Vec<ConversationId>, PresenceError>;
}

/// An event an account's sessions were sent while it had none: kept for a reconnect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissedEvent {
    pub id: String,
    /// The event, as it was sent: opaque here.
    pub payload: String,
}

#[async_trait::async_trait]
pub trait MissedEvents: Send + Sync {
    /// Those after `last_id`, oldest first.
    async fn after(&self, user: UserId, last_id: &str) -> Result<Vec<MissedEvent>, PresenceError>;
}

/// The streams from other instances that carry the presence and typing of a conversation's
/// remote members, open while a local account has the conversation open.
#[async_trait::async_trait]
pub trait PeerStreams: Send + Sync {
    async fn watch(&self, conversation: ConversationId, members: HashMap<Domain, Vec<ActorUri>>);
    async fn unwatch(&self, conversation: ConversationId);
}
