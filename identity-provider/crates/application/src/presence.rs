//! A connection's life — online, heartbeats, typing, idle, offline — and how presence and
//! typing reach the accounts that may hear of them.

use std::sync::Arc;

use domain::identity::{Accounts, ActorUri, InstanceOrigin};
use domain::messaging::Conversations;
use domain::presence::{
    ConnectionTracker, PeerStreams, PresenceAudience, PresenceBoard, PresenceError, PresenceEvent,
    PresenceNotifier, PresenceState, Signal, SignalBus, TypingEvent, may_type,
    remote_members_by_domain,
};

mod peers;

use domain::{ConnectionId, ConversationId, UserId};
pub use peers::{
    OpenPeerStream, PeerStream, PollOutcome, PollPeers, ReceivePeerSignal, ServePeerPresence,
};
use time::OffsetDateTime;

/// One live connection of an account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub user: UserId,
    pub connection: ConnectionId,
    pub actor: ActorUri,
}

async fn announce(
    bus: &dyn SignalBus,
    actor: &ActorUri,
    state: PresenceState,
    at: OffsetDateTime,
) -> Result<(), PresenceError> {
    bus.publish(&Signal::Presence(PresenceEvent {
        actor: actor.clone(),
        state,
        at,
    }))
    .await
}

/// A connection opens: the account's first one brings it online.
pub struct Connect {
    accounts: Arc<dyn Accounts>,
    tracker: Arc<ConnectionTracker>,
    bus: Arc<dyn SignalBus>,
}

impl Connect {
    pub fn new(
        accounts: Arc<dyn Accounts>,
        tracker: Arc<ConnectionTracker>,
        bus: Arc<dyn SignalBus>,
    ) -> Self {
        Self {
            accounts,
            tracker,
            bus,
        }
    }

    pub async fn execute(
        &self,
        user: UserId,
        connection: ConnectionId,
        first: bool,
        now: OffsetDateTime,
    ) -> Result<Session, PresenceError> {
        let account = self.accounts.find(user).await?.ok_or_else(|| {
            PresenceError::Unexpected(anyhow::anyhow!("the connecting account is gone"))
        })?;
        self.tracker
            .register(user, connection, account.actor_uri.clone(), now);
        if first {
            announce(&*self.bus, &account.actor_uri, PresenceState::Online, now).await?;
        }
        Ok(Session {
            user,
            connection,
            actor: account.actor_uri,
        })
    }
}

/// A connection closes: the account's last one takes it offline.
pub struct Disconnect {
    tracker: Arc<ConnectionTracker>,
    bus: Arc<dyn SignalBus>,
}

impl Disconnect {
    pub fn new(tracker: Arc<ConnectionTracker>, bus: Arc<dyn SignalBus>) -> Self {
        Self { tracker, bus }
    }

    pub async fn execute(
        &self,
        session: &Session,
        last: bool,
        now: OffsetDateTime,
    ) -> Result<(), PresenceError> {
        self.tracker.unregister(session.user, session.connection);
        if last {
            announce(&*self.bus, &session.actor, PresenceState::Offline, now).await?;
        }
        Ok(())
    }
}

/// A heartbeat, every 30 seconds: the connection is alive, and an idle account is back.
pub struct Heartbeat {
    tracker: Arc<ConnectionTracker>,
    board: Arc<PresenceBoard>,
    bus: Arc<dyn SignalBus>,
}

impl Heartbeat {
    pub fn new(
        tracker: Arc<ConnectionTracker>,
        board: Arc<PresenceBoard>,
        bus: Arc<dyn SignalBus>,
    ) -> Self {
        Self {
            tracker,
            board,
            bus,
        }
    }

    pub async fn execute(
        &self,
        session: &Session,
        now: OffsetDateTime,
    ) -> Result<(), PresenceError> {
        self.tracker.touch(session.user, session.connection, now);
        if let Some(back) = self.board.state(&session.actor).after_heartbeat() {
            announce(&*self.bus, &session.actor, back, now).await?;
        }
        Ok(())
    }
}

/// The status the account picked: Online, Idle, Do not disturb, Invisible.
pub struct SetPresence {
    bus: Arc<dyn SignalBus>,
}

impl SetPresence {
    pub fn new(bus: Arc<dyn SignalBus>) -> Self {
        Self { bus }
    }

    pub async fn execute(
        &self,
        session: &Session,
        state: PresenceState,
        now: OffsetDateTime,
    ) -> Result<(), PresenceError> {
        announce(&*self.bus, &session.actor, state, now).await
    }
}

/// `typing_start`: the account is typing in a conversation; recipients forget it after 3 s.
pub struct StartTyping {
    conversations: Arc<dyn Conversations>,
    bus: Arc<dyn SignalBus>,
}

impl StartTyping {
    pub fn new(conversations: Arc<dyn Conversations>, bus: Arc<dyn SignalBus>) -> Self {
        Self { conversations, bus }
    }

    pub async fn execute(
        &self,
        session: &Session,
        conversation: ConversationId,
        now: OffsetDateTime,
    ) -> Result<(), PresenceError> {
        // Anyone else would show as typing in a conversation they are not in.
        let members = self.conversations.members(conversation).await?;
        if !may_type(&members, &session.actor) {
            return Err(PresenceError::NotAMember);
        }
        self.bus
            .publish(&Signal::Typing(TypingEvent {
                actor: session.actor.clone(),
                conversation,
                at: now,
            }))
            .await
    }
}

/// Every minute: the accounts idle for ten minutes go `away`.
pub struct SweepIdle {
    tracker: Arc<ConnectionTracker>,
    board: Arc<PresenceBoard>,
    bus: Arc<dyn SignalBus>,
}

impl SweepIdle {
    pub fn new(
        tracker: Arc<ConnectionTracker>,
        board: Arc<PresenceBoard>,
        bus: Arc<dyn SignalBus>,
    ) -> Self {
        Self {
            tracker,
            board,
            bus,
        }
    }

    /// How many went away.
    pub async fn execute(&self, now: OffsetDateTime) -> Result<usize, PresenceError> {
        let mut away = 0;
        for actor in self.tracker.idle_actors(now) {
            if let Some(idle) = self.board.state(&actor).after_idle() {
                announce(&*self.bus, &actor, idle, now).await?;
                away += 1;
            }
        }
        Ok(away)
    }
}

/// A presence state heard on the bus: remembered, and told to the actor's local friends.
pub struct ApplyPresence {
    board: Arc<PresenceBoard>,
    audience: Arc<dyn PresenceAudience>,
    notifier: Arc<dyn PresenceNotifier>,
}

impl ApplyPresence {
    pub fn new(
        board: Arc<PresenceBoard>,
        audience: Arc<dyn PresenceAudience>,
        notifier: Arc<dyn PresenceNotifier>,
    ) -> Self {
        Self {
            board,
            audience,
            notifier,
        }
    }

    pub async fn execute(&self, event: &PresenceEvent) -> Result<(), PresenceError> {
        self.board.set(&event.actor, event.state);
        for friend in self.audience.befriended_by(&event.actor).await? {
            self.notifier.presence(friend, event);
        }
        Ok(())
    }
}

/// A typing indicator heard on the bus: to the conversation's other local members.
pub struct DeliverTyping {
    accounts: Arc<dyn Accounts>,
    conversations: Arc<dyn Conversations>,
    notifier: Arc<dyn PresenceNotifier>,
}

impl DeliverTyping {
    pub fn new(
        accounts: Arc<dyn Accounts>,
        conversations: Arc<dyn Conversations>,
        notifier: Arc<dyn PresenceNotifier>,
    ) -> Self {
        Self {
            accounts,
            conversations,
            notifier,
        }
    }

    pub async fn execute(&self, event: &TypingEvent) -> Result<(), PresenceError> {
        let members = self.conversations.members(event.conversation).await?;
        // The bus also carries what peers' streams republish: a non-member's typing goes
        // nowhere.
        if !may_type(&members, &event.actor) {
            tracing::debug!(actor = %event.actor, "typing from outside the conversation dropped");
            return Ok(());
        }
        for member in members {
            if member.actor_uri == event.actor {
                continue;
            }
            if let Some(local) = self.accounts.find_by_uri(&member.actor_uri).await? {
                self.notifier.typing(local.id, event);
            }
        }
        Ok(())
    }
}

/// `GET /api/presence`: the states the viewer's client shows on load; deltas follow over the
/// WebSocket. Only its own, its friends' and its conversations' members' are real — anyone
/// else reads `offline`, so presence never tells a stranger who is around.
pub struct ReadPresence {
    accounts: Arc<dyn Accounts>,
    board: Arc<PresenceBoard>,
    audience: Arc<dyn PresenceAudience>,
}

impl ReadPresence {
    pub fn new(
        accounts: Arc<dyn Accounts>,
        board: Arc<PresenceBoard>,
        audience: Arc<dyn PresenceAudience>,
    ) -> Self {
        Self {
            accounts,
            board,
            audience,
        }
    }

    pub async fn execute(
        &self,
        viewer: UserId,
        actors: &[ActorUri],
    ) -> Result<Vec<(ActorUri, PresenceState)>, PresenceError> {
        let account = self.accounts.find(viewer).await?.ok_or_else(|| {
            PresenceError::Unexpected(anyhow::anyhow!("the viewing account is gone"))
        })?;
        let known = self
            .audience
            .known_to(viewer, &account.actor_uri, actors)
            .await?;
        Ok(actors
            .iter()
            .map(|actor| {
                let state = if *actor == account.actor_uri || known.contains(actor) {
                    self.board.state(actor)
                } else {
                    PresenceState::Offline
                };
                (actor.clone(), state)
            })
            .collect())
    }
}

/// `watch_conversation`: while it is open here, stream its remote members' presence and typing
/// from their instances.
pub struct WatchConversation {
    origin: InstanceOrigin,
    conversations: Arc<dyn Conversations>,
    streams: Arc<dyn PeerStreams>,
}

impl WatchConversation {
    pub fn new(
        origin: InstanceOrigin,
        conversations: Arc<dyn Conversations>,
        streams: Arc<dyn PeerStreams>,
    ) -> Self {
        Self {
            origin,
            conversations,
            streams,
        }
    }

    pub async fn execute(&self, conversation: ConversationId) -> Result<(), PresenceError> {
        let members = self.conversations.members(conversation).await?;
        let remote = remote_members_by_domain(&members, &self.origin);
        if !remote.is_empty() {
            self.streams.watch(conversation, remote).await;
        }
        Ok(())
    }

    /// `unwatch_conversation`: a stream no conversation needs any more closes.
    pub async fn stop(&self, conversation: ConversationId) {
        self.streams.unwatch(conversation).await;
    }
}

#[cfg(test)]
mod tests;
