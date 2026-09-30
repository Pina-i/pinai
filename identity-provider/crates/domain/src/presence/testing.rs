//! In-memory fakes of the presence ports and the contract every store must satisfy.

use std::collections::{HashMap, VecDeque};
use std::pin::Pin;
use std::sync::Mutex;
use std::task::{Context, Poll};

use futures_core::Stream;
use futures_core::stream::BoxStream;

use crate::identity::{Account, ActorUri, Domain};
use crate::{ConversationId, UserId};

use super::{
    MissedEvent, MissedEvents, PeerPresence, PeerStreams, PresenceAudience, PresenceError,
    PresenceEvent, PresenceNotifier, PresenceState, Signal, SignalBus, SignalFeed, TypingEvent,
};

#[derive(Default)]
pub struct RecordingBus {
    published: Mutex<Vec<Signal>>,
}

impl RecordingBus {
    pub fn published(&self) -> Vec<Signal> {
        self.published.lock().unwrap().clone()
    }

    /// Only the presence states published, in order.
    pub fn states(&self) -> Vec<(ActorUri, PresenceState)> {
        self.published()
            .into_iter()
            .filter_map(|signal| match signal {
                Signal::Presence(event) => Some((event.actor, event.state)),
                Signal::Typing(_) => None,
            })
            .collect()
    }
}

#[async_trait::async_trait]
impl SignalBus for RecordingBus {
    async fn publish(&self, signal: &Signal) -> Result<(), PresenceError> {
        self.published.lock().unwrap().push(signal.clone());
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pushed {
    Presence(UserId, PresenceEvent),
    Typing(UserId, TypingEvent),
}

#[derive(Default)]
pub struct RecordingPresenceNotifier {
    pushed: Mutex<Vec<Pushed>>,
}

impl RecordingPresenceNotifier {
    pub fn pushed(&self) -> Vec<Pushed> {
        self.pushed.lock().unwrap().clone()
    }

    /// Who was told, sorted.
    pub fn recipients(&self) -> Vec<UserId> {
        let mut to: Vec<UserId> = self
            .pushed()
            .into_iter()
            .map(|p| match p {
                Pushed::Presence(to, _) | Pushed::Typing(to, _) => to,
            })
            .collect();
        to.sort();
        to
    }
}

impl PresenceNotifier for RecordingPresenceNotifier {
    fn presence(&self, to: UserId, event: &PresenceEvent) {
        self.pushed
            .lock()
            .unwrap()
            .push(Pushed::Presence(to, event.clone()));
    }

    fn typing(&self, to: UserId, event: &TypingEvent) {
        self.pushed
            .lock()
            .unwrap()
            .push(Pushed::Typing(to, event.clone()));
    }
}

/// Seeds the friendships and conversations the audience reads; the other contexts write them.
#[async_trait::async_trait]
pub trait Relationships: Send + Sync {
    /// `owner` counts `friend` among its friends — accepted, or only asked.
    async fn befriend(&self, owner: &Account, friend: &ActorUri, accepted: bool);
    /// A conversation holding `members`, all active.
    async fn converse(&self, members: &[&ActorUri]) -> ConversationId;
    async fn leave(&self, conversation: ConversationId, member: &ActorUri);
}

#[derive(Default)]
pub struct InMemoryAudience {
    state: Mutex<AudienceState>,
}

#[derive(Default)]
struct AudienceState {
    friendships: Vec<(UserId, ActorUri, bool)>,
    /// The owners' actors, by account.
    owners: HashMap<UserId, ActorUri>,
    /// `(conversation, member, active)`.
    members: Vec<(ConversationId, ActorUri, bool)>,
}

impl AudienceState {
    /// The active conversations `actor` is in with an active member on `peer`.
    fn shares_with<'a>(
        &'a self,
        peer: &'a Domain,
        actor: &'a ActorUri,
    ) -> impl Iterator<Item = ConversationId> + 'a {
        self.members
            .iter()
            .filter(move |(_, member, active)| *active && member == actor)
            .map(|(conversation, _, _)| *conversation)
            .filter(move |conversation| {
                self.members
                    .iter()
                    .any(|(c, them, active)| c == conversation && *active && them.domain() == peer)
            })
    }
}

fn sorted(mut actors: Vec<ActorUri>) -> Vec<ActorUri> {
    actors.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    actors.dedup();
    actors
}

#[async_trait::async_trait]
impl Relationships for InMemoryAudience {
    async fn befriend(&self, owner: &Account, friend: &ActorUri, accepted: bool) {
        let mut state = self.state.lock().unwrap();
        state.owners.insert(owner.id, owner.actor_uri.clone());
        state.friendships.push((owner.id, friend.clone(), accepted));
    }

    async fn converse(&self, members: &[&ActorUri]) -> ConversationId {
        let id = ConversationId::generate();
        let mut state = self.state.lock().unwrap();
        state
            .members
            .extend(members.iter().map(|m| (id, (*m).clone(), true)));
        id
    }

    async fn leave(&self, conversation: ConversationId, member: &ActorUri) {
        let mut state = self.state.lock().unwrap();
        for held in state
            .members
            .iter_mut()
            .filter(|(c, m, _)| *c == conversation && m == member)
        {
            held.2 = false;
        }
    }
}

#[async_trait::async_trait]
impl PresenceAudience for InMemoryAudience {
    async fn befriended_by(&self, actor: &ActorUri) -> Result<Vec<UserId>, PresenceError> {
        let state = self.state.lock().unwrap();
        let mut owners: Vec<UserId> = state
            .friendships
            .iter()
            .filter(|(_, friend, accepted)| friend == actor && *accepted)
            .map(|(owner, _, _)| *owner)
            .collect();
        owners.sort();
        owners.dedup();
        Ok(owners)
    }

    async fn known_to(
        &self,
        viewer: UserId,
        viewer_actor: &ActorUri,
        among: &[ActorUri],
    ) -> Result<Vec<ActorUri>, PresenceError> {
        let state = self.state.lock().unwrap();
        let active_in = |c: ConversationId, actor: &ActorUri| {
            state
                .members
                .iter()
                .any(|(conv, m, active)| *conv == c && m == actor && *active)
        };
        let shares = |actor: &ActorUri| {
            state
                .members
                .iter()
                .any(|(c, m, active)| m == actor && *active && active_in(*c, viewer_actor))
        };
        let befriended = |actor: &ActorUri| {
            state
                .friendships
                .iter()
                .any(|(owner, friend, accepted)| *owner == viewer && friend == actor && *accepted)
        };
        let mut known: Vec<ActorUri> = among
            .iter()
            .filter(|actor| befriended(actor) || shares(actor))
            .cloned()
            .collect();
        known.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        known.dedup();
        Ok(known)
    }

    async fn befriended(&self) -> Result<Vec<ActorUri>, PresenceError> {
        let state = self.state.lock().unwrap();
        let mut friends: Vec<ActorUri> = state
            .friendships
            .iter()
            .filter(|(_, _, accepted)| *accepted)
            .map(|(_, friend, _)| friend.clone())
            .collect();
        friends.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        friends.dedup();
        Ok(friends)
    }

    async fn known_on(
        &self,
        peer: &Domain,
        among: &[ActorUri],
    ) -> Result<Vec<ActorUri>, PresenceError> {
        let state = self.state.lock().unwrap();
        let befriends = |actor: &ActorUri| {
            state.friendships.iter().any(|(owner, friend, accepted)| {
                *accepted && friend.domain() == peer && state.owners.get(owner) == Some(actor)
            })
        };
        let known: Vec<ActorUri> = among
            .iter()
            .filter(|actor| befriends(actor) || state.shares_with(peer, actor).next().is_some())
            .cloned()
            .collect();
        Ok(sorted(known))
    }

    async fn conversations_with(
        &self,
        peer: &Domain,
        among: &[ActorUri],
    ) -> Result<Vec<ConversationId>, PresenceError> {
        let state = self.state.lock().unwrap();
        let mut shared: Vec<ConversationId> = among
            .iter()
            .flat_map(|actor| state.shares_with(peer, actor))
            .collect();
        shared.sort();
        shared.dedup();
        Ok(shared)
    }
}

#[derive(Default)]
pub struct InMemoryMissedEvents {
    events: Mutex<Vec<(UserId, MissedEvent)>>,
}

impl InMemoryMissedEvents {
    pub fn keep(&self, user: UserId, id: &str, payload: &str) {
        self.events.lock().unwrap().push((
            user,
            MissedEvent {
                id: id.to_owned(),
                payload: payload.to_owned(),
            },
        ));
    }
}

#[async_trait::async_trait]
impl MissedEvents for InMemoryMissedEvents {
    async fn after(&self, user: UserId, last_id: &str) -> Result<Vec<MissedEvent>, PresenceError> {
        let events = self.events.lock().unwrap();
        let mine: Vec<&MissedEvent> = events
            .iter()
            .filter(|(u, _)| *u == user)
            .map(|(_, e)| e)
            .collect();
        let start = mine
            .iter()
            .position(|e| e.id == last_id)
            .map_or(0, |i| i + 1);
        Ok(mine[start..].iter().map(|e| (*e).clone()).collect())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Watch {
    Opened(ConversationId, HashMap<Domain, Vec<ActorUri>>),
    Closed(ConversationId),
}

#[derive(Default)]
pub struct RecordingPeerStreams {
    calls: Mutex<Vec<Watch>>,
}

impl RecordingPeerStreams {
    pub fn calls(&self) -> Vec<Watch> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl PeerStreams for RecordingPeerStreams {
    async fn watch(&self, conversation: ConversationId, members: HashMap<Domain, Vec<ActorUri>>) {
        self.calls
            .lock()
            .unwrap()
            .push(Watch::Opened(conversation, members));
    }

    async fn unwatch(&self, conversation: ConversationId) {
        self.calls.lock().unwrap().push(Watch::Closed(conversation));
    }
}

/// The bus as one listener hears it: the signals queued so far, then its end — or, held open,
/// nothing more.
#[derive(Default)]
pub struct QueuedFeed {
    queued: Mutex<Vec<Signal>>,
    held_open: bool,
}

impl QueuedFeed {
    /// A feed whose streams, once drained, stay open as a live bus does.
    pub fn held_open() -> Self {
        Self {
            held_open: true,
            ..Self::default()
        }
    }

    pub fn queue(&self, signal: Signal) {
        self.queued.lock().unwrap().push(signal);
    }
}

struct Drain {
    queued: VecDeque<Signal>,
    held_open: bool,
}

impl Stream for Drain {
    type Item = Signal;

    fn poll_next(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Signal>> {
        match self.queued.pop_front() {
            None if self.held_open => Poll::Pending,
            next => Poll::Ready(next),
        }
    }
}

#[async_trait::async_trait]
impl SignalFeed for QueuedFeed {
    async fn subscribe(&self) -> Result<BoxStream<'static, Signal>, PresenceError> {
        let queued = std::mem::take(&mut *self.queued.lock().unwrap());
        Ok(Box::pin(Drain {
            queued: queued.into(),
            held_open: self.held_open,
        }))
    }
}

/// Peers that answer polls with the states given them; an instance given none fails.
#[derive(Default)]
pub struct ScriptedPeers {
    answers: Mutex<HashMap<Domain, Vec<(ActorUri, PresenceState)>>>,
    asked: Mutex<Vec<(Domain, Vec<ActorUri>)>>,
}

impl ScriptedPeers {
    pub fn answer(&self, peer: &Domain, states: &[(&ActorUri, PresenceState)]) {
        self.answers.lock().unwrap().insert(
            peer.clone(),
            states
                .iter()
                .map(|(actor, state)| ((*actor).clone(), *state))
                .collect(),
        );
    }

    /// Every poll, each asking's actors sorted.
    pub fn asked(&self) -> Vec<(Domain, Vec<ActorUri>)> {
        self.asked.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl PeerPresence for ScriptedPeers {
    async fn poll(
        &self,
        peer: &Domain,
        actors: &[ActorUri],
    ) -> Result<Vec<(ActorUri, PresenceState)>, PresenceError> {
        let mut sorted = actors.to_vec();
        sorted.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        self.asked.lock().unwrap().push((peer.clone(), sorted));
        self.answers
            .lock()
            .unwrap()
            .get(peer)
            .cloned()
            .ok_or_else(|| PresenceError::Unexpected(anyhow::anyhow!("{peer} did not answer")))
    }
}

/// What every presence audience must do.
pub mod contract {
    use super::*;
    use crate::identity::testing::remote_actor;

    pub async fn an_actor_is_heard_by_the_accounts_that_befriended_it(
        audience: &dyn PresenceAudience,
        relationships: &dyn Relationships,
        alice: &Account,
        bob: &Account,
    ) {
        let carol = remote_actor("carol_k2m9x@idp.carol.test").actor_uri;
        relationships.befriend(alice, &carol, true).await;
        relationships.befriend(bob, &carol, false).await;

        let heard_by = audience.befriended_by(&carol).await.unwrap();

        assert_eq!(heard_by, vec![alice.id]);
        assert!(
            audience
                .befriended_by(&alice.actor_uri)
                .await
                .unwrap()
                .is_empty()
        );
    }

    pub async fn a_viewer_knows_its_friends_and_the_members_of_its_conversations(
        audience: &dyn PresenceAudience,
        relationships: &dyn Relationships,
        alice: &Account,
        bob: &Account,
    ) {
        let remote = |name: &str| remote_actor(&format!("{name}_k2m9x@idp.peer.test")).actor_uri;
        let (carol, dave, erin, frank, gina) = (
            remote("carol"),
            remote("dave"),
            remote("erin"),
            remote("frank"),
            remote("gina"),
        );
        relationships.befriend(alice, &carol, true).await;
        relationships.befriend(alice, &gina, false).await;
        relationships.befriend(bob, &frank, true).await;
        relationships
            .converse(&[&alice.actor_uri, &bob.actor_uri, &dave])
            .await;
        let left = relationships.converse(&[&alice.actor_uri, &erin]).await;
        relationships.leave(left, &erin).await;
        let quit = relationships.converse(&[&alice.actor_uri, &frank]).await;
        relationships.leave(quit, &alice.actor_uri).await;

        let known = audience
            .known_to(
                alice.id,
                &alice.actor_uri,
                &[
                    bob.actor_uri.clone(),
                    carol.clone(),
                    dave.clone(),
                    erin,
                    frank,
                    gina,
                ],
            )
            .await
            .unwrap();

        let mut expected = vec![bob.actor_uri.clone(), carol, dave];
        expected.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        let mut known = known;
        known.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        assert_eq!(known, expected);
        assert!(
            audience
                .known_to(alice.id, &alice.actor_uri, &[])
                .await
                .unwrap()
                .is_empty()
        );
    }

    pub async fn every_accepted_friend_of_a_local_account_is_befriended(
        audience: &dyn PresenceAudience,
        relationships: &dyn Relationships,
        alice: &Account,
        bob: &Account,
    ) {
        let (carol, dave) = (
            remote_actor("carol_k2m9x@idp.carol.test").actor_uri,
            remote_actor("dave_k2m9x@idp.dave.test").actor_uri,
        );
        relationships.befriend(alice, &carol, true).await;
        relationships.befriend(bob, &carol, true).await;
        relationships.befriend(alice, &bob.actor_uri, true).await;
        relationships.befriend(bob, &dave, false).await;

        let mut befriended = audience.befriended().await.unwrap();
        befriended.sort_by(|a, b| a.as_str().cmp(b.as_str()));

        let mut expected = vec![bob.actor_uri.clone(), carol];
        expected.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        assert_eq!(befriended, expected);
    }

    pub async fn a_peer_knows_the_accounts_its_users_befriended_or_share_a_conversation_with(
        audience: &dyn PresenceAudience,
        relationships: &dyn Relationships,
        alice: &Account,
        bob: &Account,
    ) {
        let peer = |name: &str| remote_actor(&format!("{name}_k2m9x@idp.carol.test")).actor_uri;
        let (carol, erin, frank, grace) =
            (peer("carol"), peer("erin"), peer("frank"), peer("grace"));
        let dave = remote_actor("dave_k2m9x@idp.dave.test").actor_uri;
        let among = [alice.actor_uri.clone(), bob.actor_uri.clone()];
        relationships.befriend(alice, &carol, false).await;
        relationships.befriend(bob, &dave, true).await;
        relationships.converse(&[&bob.actor_uri, &dave]).await;
        let left = relationships.converse(&[&bob.actor_uri, &erin]).await;
        relationships.leave(left, &erin).await;
        let quit = relationships.converse(&[&alice.actor_uri, &grace]).await;
        relationships.leave(quit, &alice.actor_uri).await;

        let before = audience.known_on(carol.domain(), &among).await.unwrap();
        relationships.befriend(alice, &erin, true).await;
        relationships.converse(&[&bob.actor_uri, &frank]).await;
        let mut after = audience.known_on(carol.domain(), &among).await.unwrap();
        after.sort_by(|a, b| a.as_str().cmp(b.as_str()));

        let mut expected = among.to_vec();
        expected.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        assert!(before.is_empty(), "{before:?}");
        assert_eq!(after, expected);
    }

    pub async fn a_peer_follows_the_conversations_it_has_a_member_in(
        audience: &dyn PresenceAudience,
        relationships: &dyn Relationships,
        alice: &Account,
        bob: &Account,
    ) {
        let peer = |name: &str| remote_actor(&format!("{name}_k2m9x@idp.carol.test")).actor_uri;
        let (carol, erin) = (peer("carol"), peer("erin"));
        let dave = remote_actor("dave_k2m9x@idp.dave.test").actor_uri;
        let dm = relationships.converse(&[&alice.actor_uri, &carol]).await;
        let group = relationships
            .converse(&[&alice.actor_uri, &bob.actor_uri, &carol, &dave])
            .await;
        relationships
            .converse(&[&alice.actor_uri, &bob.actor_uri, &dave])
            .await;
        let left = relationships.converse(&[&bob.actor_uri, &erin]).await;
        relationships.leave(left, &erin).await;
        let quit = relationships.converse(&[&bob.actor_uri, &carol]).await;
        relationships.leave(quit, &bob.actor_uri).await;
        relationships.converse(&[&carol, &dave]).await;

        let mut followed = audience
            .conversations_with(
                carol.domain(),
                &[alice.actor_uri.clone(), bob.actor_uri.clone()],
            )
            .await
            .unwrap();
        followed.sort();

        let mut expected = vec![dm, group];
        expected.sort();
        assert_eq!(followed, expected);
        assert!(
            audience
                .conversations_with(carol.domain(), &[])
                .await
                .unwrap()
                .is_empty()
        );
    }
}

#[cfg(test)]
mod tests;
