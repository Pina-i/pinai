//! Presence across instances: what this instance serves its peers, and what it hears from them.

use std::collections::HashSet;
use std::sync::Arc;

use domain::identity::{ActorUri, Domain, InstanceOrigin};
use domain::presence::{
    PeerFilter, PeerPresence, PollTargets, PresenceAudience, PresenceBoard, PresenceError,
    PresenceEvent, PresenceState, Signal, SignalBus, SignalFeed, speaks_for,
};
use domain::social::FriendPresence;
use futures_core::stream::BoxStream;
use futures_util::StreamExt;
use futures_util::stream::FuturesUnordered;
use time::OffsetDateTime;

use super::announce;

/// The accounts here among `actors` that an account on `peer` may follow: its friends, and the
/// members of its conversations. Another instance's actors are its own to tell of.
async fn followed_from(
    origin: &InstanceOrigin,
    audience: &dyn PresenceAudience,
    peer: &Domain,
    actors: &[ActorUri],
) -> Result<HashSet<ActorUri>, PresenceError> {
    let local: Vec<ActorUri> = actors
        .iter()
        .filter(|actor| origin.owns(actor))
        .cloned()
        .collect();
    if local.is_empty() {
        return Ok(HashSet::new());
    }
    Ok(audience.known_on(peer, &local).await?.into_iter().collect())
}

/// `POST /api/presence/batch`: a peer polling the presence behind its users' friends lists. As
/// for a local viewer, whoever its users do not know reads `offline`.
pub struct ServePeerPresence {
    origin: InstanceOrigin,
    board: Arc<PresenceBoard>,
    audience: Arc<dyn PresenceAudience>,
}

impl ServePeerPresence {
    pub fn new(
        origin: InstanceOrigin,
        board: Arc<PresenceBoard>,
        audience: Arc<dyn PresenceAudience>,
    ) -> Self {
        Self {
            origin,
            board,
            audience,
        }
    }

    pub async fn execute(
        &self,
        peer: &Domain,
        actors: &[ActorUri],
    ) -> Result<Vec<(ActorUri, PresenceState)>, PresenceError> {
        let followed = followed_from(&self.origin, &*self.audience, peer, actors).await?;
        Ok(actors
            .iter()
            .map(|actor| {
                let state = if followed.contains(actor) {
                    self.board.state(actor)
                } else {
                    PresenceState::Offline
                };
                (actor.clone(), state)
            })
            .collect())
    }
}

/// A peer's stream: the last states heard, then the signals as they come.
pub struct PeerStream {
    pub replay: Vec<PresenceEvent>,
    pub live: BoxStream<'static, Signal>,
}

/// `GET /api/presence/stream`: a peer following the accounts in a conversation open there —
/// those its users know, typing only in the conversations it has a member in.
pub struct OpenPeerStream {
    origin: InstanceOrigin,
    board: Arc<PresenceBoard>,
    audience: Arc<dyn PresenceAudience>,
    feed: Arc<dyn SignalFeed>,
}

impl OpenPeerStream {
    pub fn new(
        origin: InstanceOrigin,
        board: Arc<PresenceBoard>,
        audience: Arc<dyn PresenceAudience>,
        feed: Arc<dyn SignalFeed>,
    ) -> Self {
        Self {
            origin,
            board,
            audience,
            feed,
        }
    }

    pub async fn execute(
        &self,
        peer: &Domain,
        actors: &[ActorUri],
        now: OffsetDateTime,
    ) -> Result<PeerStream, PresenceError> {
        // Listening before the replay is read: a change in between comes after it, not never.
        let live = self.feed.subscribe().await?;
        let followed = followed_from(&self.origin, &*self.audience, peer, actors).await?;
        let conversations = if followed.is_empty() {
            HashSet::new()
        } else {
            let followed: Vec<ActorUri> = followed.iter().cloned().collect();
            self.audience
                .conversations_with(peer, &followed)
                .await?
                .into_iter()
                .collect()
        };
        let filter = PeerFilter {
            actors: followed,
            conversations,
        };
        let replay = filter
            .actors
            .iter()
            .filter_map(|actor| {
                Some(PresenceEvent {
                    actor: actor.clone(),
                    state: self.board.heard(actor)?,
                    at: now,
                })
            })
            .collect();
        let live = live.filter(move |signal| std::future::ready(filter.admits(signal)));
        Ok(PeerStream {
            replay,
            live: Box::pin(live),
        })
    }
}

/// What one round of polls changed, and the peers that did not answer.
#[derive(Debug, Default)]
pub struct PollOutcome {
    pub changed: usize,
    pub failed: Vec<(Domain, PresenceError)>,
}

/// Every 10 s: the remote friends' presence, asked of their instances; a change is announced on
/// the bus like a local one.
pub struct PollPeers {
    targets: Arc<PollTargets>,
    audience: Arc<dyn PresenceAudience>,
    peers: Arc<dyn PeerPresence>,
    board: Arc<PresenceBoard>,
    bus: Arc<dyn SignalBus>,
}

impl PollPeers {
    pub fn new(
        targets: Arc<PollTargets>,
        audience: Arc<dyn PresenceAudience>,
        peers: Arc<dyn PeerPresence>,
        board: Arc<PresenceBoard>,
        bus: Arc<dyn SignalBus>,
    ) -> Self {
        Self {
            targets,
            audience,
            peers,
            board,
            bus,
        }
    }

    /// At startup: every friend of a local account; the social context keeps them after. How
    /// many are polled.
    pub async fn prime(&self) -> Result<usize, PresenceError> {
        for friend in self.audience.befriended().await? {
            self.targets.watch(&friend);
        }
        Ok(self.targets.snapshot().values().map(Vec::len).sum())
    }

    /// Every peer at once: a slow one delays only its own friends, by at most its timeout.
    pub async fn execute(&self, now: OffsetDateTime) -> PollOutcome {
        let mut polls: FuturesUnordered<_> = self
            .targets
            .snapshot()
            .into_iter()
            .map(|(peer, actors)| async move {
                let polled = self.poll(&peer, &actors, now).await;
                (peer, polled)
            })
            .collect();
        let mut outcome = PollOutcome::default();
        while let Some((peer, polled)) = polls.next().await {
            match polled {
                Ok(changed) => outcome.changed += changed,
                Err(e) => outcome.failed.push((peer, e)),
            }
        }
        outcome
    }

    async fn poll(
        &self,
        peer: &Domain,
        actors: &[ActorUri],
        now: OffsetDateTime,
    ) -> Result<usize, PresenceError> {
        let asked: HashSet<&ActorUri> = actors.iter().collect();
        let mut changed = 0;
        for (actor, state) in self.peers.poll(peer, actors).await? {
            // Asked only of its own accounts: anything else in the answer is the peer's invention.
            if !asked.contains(&actor) {
                continue;
            }
            if self.board.state(&actor) != state {
                self.board.set(&actor, state);
                announce(&*self.bus, &actor, state, now).await?;
                changed += 1;
            }
        }
        Ok(changed)
    }
}

/// A signal a peer's stream carried: onto this instance's bus, to the local accounts that may
/// hear of it.
pub struct ReceivePeerSignal {
    bus: Arc<dyn SignalBus>,
}

impl ReceivePeerSignal {
    pub fn new(bus: Arc<dyn SignalBus>) -> Self {
        Self { bus }
    }

    pub async fn execute(&self, peer: &Domain, signal: &Signal) -> Result<(), PresenceError> {
        // Else a peer could put anyone online here, or have them type in any conversation.
        if !speaks_for(peer, signal) {
            tracing::debug!(%peer, actor = %signal.actor(), "a peer's signal for another instance dropped");
            return Ok(());
        }
        self.bus.publish(signal).await
    }
}

#[cfg(test)]
mod tests;
