//! In-memory fakes of the social ports and the contract every `SocialGraph` must satisfy.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::identity::{Account, ActorUri, RemoteActor};
use crate::messaging::{ConversationKind, may_hold_dm};
use crate::{ConversationId, FriendshipId, UserId};

use super::{
    Direction, FriendPresence, FriendView, Friendship, FriendshipEvent, FriendshipStatus,
    LocalRequest, SocialFederation, SocialGraph, SocialNotifier, SocialStoreError, Unfriended,
};

/// Changes a local account as its owner does — outside the graph, which only reads it.
#[async_trait::async_trait]
pub trait AccountEdits: Send + Sync {
    /// The account's name and avatar become `account`'s.
    async fn save(&self, account: &Account);
}

#[derive(Default)]
pub struct InMemorySocialGraph {
    sides: Mutex<Vec<Friendship>>,
    /// The actor URI of every local account the graph has seen — what tells a local friend.
    locals: Mutex<HashMap<UserId, Account>>,
    /// DM conversations, by their two members.
    dms: Mutex<Vec<(ActorUri, ActorUri, ConversationId)>>,
    /// The avatar each side keeps of a remote friend, as it was met.
    met_with: Mutex<HashMap<(UserId, ActorUri), String>>,
}

impl InMemorySocialGraph {
    /// A new side keeps the avatar; an existing one, the avatar it had.
    fn meet(&self, owner: UserId, friend: &ActorUri, avatar_url: Option<&str>) {
        if let Some(url) = avatar_url {
            self.met_with
                .lock()
                .unwrap()
                .entry((owner, friend.clone()))
                .or_insert_with(|| url.to_owned());
        }
    }

    /// Seed a side as a test's starting state.
    pub fn insert(&self, side: Friendship) {
        self.sides.lock().unwrap().push(side);
    }

    /// The pending-request upsert: a pending side is taken over by the new request, an accepted
    /// one is returned untouched.
    fn request_side(
        sides: &mut Vec<Friendship>,
        owner: UserId,
        friend: &ActorUri,
        direction: Direction,
    ) -> Friendship {
        if let Some(side) = sides
            .iter_mut()
            .find(|s| s.owner == owner && &s.friend == friend)
        {
            if side.status == FriendshipStatus::Pending {
                side.direction = direction;
            }
            return side.clone();
        }
        let side = Friendship {
            id: FriendshipId::generate(),
            owner,
            friend: friend.clone(),
            status: FriendshipStatus::Pending,
            direction,
        };
        sides.push(side.clone());
        side
    }
}

#[async_trait::async_trait]
impl SocialGraph for InMemorySocialGraph {
    async fn record_local_request(
        &self,
        requester: &Account,
        target: &Account,
    ) -> Result<LocalRequest, SocialStoreError> {
        let mut locals = self.locals.lock().unwrap();
        locals.insert(requester.id, requester.clone());
        locals.insert(target.id, target.clone());
        let mut sides = self.sides.lock().unwrap();
        Ok(LocalRequest {
            requester_side: Self::request_side(
                &mut sides,
                requester.id,
                &target.actor_uri,
                Direction::Outgoing,
            ),
            target_side: Self::request_side(
                &mut sides,
                target.id,
                &requester.actor_uri,
                Direction::Incoming,
            ),
        })
    }

    async fn record_outgoing(
        &self,
        owner: UserId,
        friend: &ActorUri,
        friend_avatar_url: Option<&str>,
    ) -> Result<Friendship, SocialStoreError> {
        self.meet(owner, friend, friend_avatar_url);
        let mut sides = self.sides.lock().unwrap();
        Ok(Self::request_side(
            &mut sides,
            owner,
            friend,
            Direction::Outgoing,
        ))
    }

    async fn accept(
        &self,
        request: &Friendship,
        accepter: &Account,
    ) -> Result<ConversationId, SocialStoreError> {
        let locals = self.locals.lock().unwrap();
        let mut sides = self.sides.lock().unwrap();
        let side = sides
            .iter_mut()
            .find(|s| {
                s.id == request.id
                    && s.status == FriendshipStatus::Pending
                    && s.direction == Direction::Incoming
            })
            .ok_or(SocialStoreError::Conflict)?;
        side.status = FriendshipStatus::Accepted;
        let requester_side = sides.iter_mut().find(|s| {
            s.friend == accepter.actor_uri
                && locals.get(&s.owner).map(|a| &a.actor_uri) == Some(&request.friend)
        });
        if let Some(requester_side) = requester_side {
            requester_side.status = FriendshipStatus::Accepted;
        }
        let mut dms = self.dms.lock().unwrap();
        let (a, b) = (&accepter.actor_uri, &request.friend);
        let existing = dms
            .iter()
            .find(|(x, y, _)| (x == a && y == b) || (x == b && y == a))
            .map(|(_, _, id)| *id);
        Ok(existing.unwrap_or_else(|| {
            let id = ConversationId::generate();
            dms.push((a.clone(), b.clone(), id));
            id
        }))
    }

    async fn decline(
        &self,
        request: &Friendship,
        decliner: &Account,
    ) -> Result<(), SocialStoreError> {
        let locals = self.locals.lock().unwrap();
        let mut sides = self.sides.lock().unwrap();
        let before = sides.len();
        sides.retain(|s| {
            !(s.id == request.id
                && s.status == FriendshipStatus::Pending
                && s.direction == Direction::Incoming)
        });
        if sides.len() == before {
            return Err(SocialStoreError::Conflict);
        }
        sides.retain(|s| {
            !(s.friend == decliner.actor_uri
                && locals.get(&s.owner).map(|a| &a.actor_uri) == Some(&request.friend))
        });
        Ok(())
    }

    async fn unfriend(
        &self,
        owner: &Account,
        friend: &ActorUri,
    ) -> Result<Option<Unfriended>, SocialStoreError> {
        let locals = self.locals.lock().unwrap();
        let mut sides = self.sides.lock().unwrap();
        let Some(at) = sides
            .iter()
            .position(|s| s.owner == owner.id && &s.friend == friend)
        else {
            return Ok(None);
        };
        let removed = sides.remove(at);
        let reverse = sides
            .iter()
            .position(|s| {
                s.friend == owner.actor_uri
                    && locals.get(&s.owner).map(|a| &a.actor_uri) == Some(friend)
            })
            .map(|at| sides.remove(at));
        Ok(Some(Unfriended { removed, reverse }))
    }

    async fn befriended_by_anyone(&self, friend: &ActorUri) -> Result<bool, SocialStoreError> {
        let sides = self.sides.lock().unwrap();
        Ok(sides
            .iter()
            .any(|s| &s.friend == friend && s.status == FriendshipStatus::Accepted))
    }

    async fn incoming_requests(&self, owner: UserId) -> Result<Vec<Friendship>, SocialStoreError> {
        let sides = self.sides.lock().unwrap();
        Ok(sides
            .iter()
            .rev()
            .filter(|s| {
                s.owner == owner
                    && s.status == FriendshipStatus::Pending
                    && s.direction == Direction::Incoming
            })
            .cloned()
            .collect())
    }

    async fn friends(&self, owner: UserId) -> Result<Vec<FriendView>, SocialStoreError> {
        let locals = self.locals.lock().unwrap();
        let sides = self.sides.lock().unwrap();
        let met_with = self.met_with.lock().unwrap();
        Ok(sides
            .iter()
            .filter(|s| s.owner == owner && s.status == FriendshipStatus::Accepted)
            .map(|s| {
                let local = locals.values().find(|a| a.actor_uri == s.friend);
                FriendView {
                    username: local.map(|a| a.username.clone()),
                    display_name: local.and_then(|a| a.display_name.clone()),
                    avatar_url: match local {
                        Some(account) => account.avatar_url.clone(),
                        None => met_with.get(&(s.owner, s.friend.clone())).cloned(),
                    },
                    actor_uri: s.friend.clone(),
                    instance: match local {
                        Some(_) => "local".to_owned(),
                        None => s.friend.domain().to_string(),
                    },
                }
            })
            .collect())
    }

    async fn record_incoming(
        &self,
        owner: UserId,
        friend: &ActorUri,
        friend_avatar_url: Option<&str>,
    ) -> Result<Friendship, SocialStoreError> {
        self.meet(owner, friend, friend_avatar_url);
        let mut sides = self.sides.lock().unwrap();
        Ok(Self::request_side(
            &mut sides,
            owner,
            friend,
            Direction::Incoming,
        ))
    }

    async fn accept_outgoing(
        &self,
        owner: &Account,
        accepter: &ActorUri,
        advertised: Option<ConversationId>,
    ) -> Result<Option<(Friendship, ConversationId)>, SocialStoreError> {
        let mut sides = self.sides.lock().unwrap();
        let Some(side) = sides.iter_mut().find(|s| {
            s.owner == owner.id
                && &s.friend == accepter
                && s.status == FriendshipStatus::Pending
                && s.direction == Direction::Outgoing
        }) else {
            return Ok(None);
        };
        side.status = FriendshipStatus::Accepted;
        let side = side.clone();
        let mut dms = self.dms.lock().unwrap();
        let (a, b) = (&owner.actor_uri, accepter);
        let existing = dms
            .iter()
            .find(|(x, y, _)| (x == a && y == b) || (x == b && y == a))
            .map(|(_, _, id)| *id);
        let dm = existing.unwrap_or_else(|| {
            // An id another pair's DM holds is never reused for this one.
            let taken = |id: &ConversationId| {
                dms.iter().any(|(x, y, held)| {
                    held == id && !may_hold_dm(ConversationKind::Dm, &[x.clone(), y.clone()], a, b)
                })
            };
            let id = advertised
                .filter(|id| !taken(id))
                .unwrap_or_else(ConversationId::generate);
            dms.push((a.clone(), b.clone(), id));
            id
        });
        Ok(Some((side, dm)))
    }

    async fn drop_outgoing(
        &self,
        owner: UserId,
        friend: &ActorUri,
    ) -> Result<bool, SocialStoreError> {
        let mut sides = self.sides.lock().unwrap();
        let before = sides.len();
        sides.retain(|s| {
            !(s.owner == owner
                && &s.friend == friend
                && s.status == FriendshipStatus::Pending
                && s.direction == Direction::Outgoing)
        });
        Ok(sides.len() < before)
    }

    async fn dm_between(
        &self,
        a: &ActorUri,
        b: &ActorUri,
    ) -> Result<Option<ConversationId>, SocialStoreError> {
        let dms = self.dms.lock().unwrap();
        Ok(dms
            .iter()
            .find(|(x, y, _)| (x == a && y == b) || (x == b && y == a))
            .map(|(_, _, id)| *id))
    }

    async fn find(&self, id: FriendshipId) -> Result<Option<Friendship>, SocialStoreError> {
        Ok(self
            .sides
            .lock()
            .unwrap()
            .iter()
            .find(|s| s.id == id)
            .cloned())
    }

    async fn between(
        &self,
        owner: UserId,
        friend: &ActorUri,
    ) -> Result<Option<Friendship>, SocialStoreError> {
        let sides = self.sides.lock().unwrap();
        Ok(sides
            .iter()
            .find(|s| s.owner == owner && &s.friend == friend)
            .cloned())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Notice {
    FriendRequest,
    FriendAccepted,
    FriendRemoved,
}

/// Records every notice, in order.
#[derive(Default)]
pub struct RecordingSocialNotifier {
    sent: Mutex<Vec<(Notice, UserId, FriendshipEvent)>>,
}

impl RecordingSocialNotifier {
    pub fn sent(&self) -> Vec<(Notice, UserId, FriendshipEvent)> {
        self.sent.lock().unwrap().clone()
    }
}

impl SocialNotifier for RecordingSocialNotifier {
    fn friend_removed(&self, to: UserId, event: &FriendshipEvent) {
        let notice = (Notice::FriendRemoved, to, event.clone());
        self.sent.lock().unwrap().push(notice);
    }

    fn friend_accepted(&self, to: UserId, event: &FriendshipEvent) {
        let notice = (Notice::FriendAccepted, to, event.clone());
        self.sent.lock().unwrap().push(notice);
    }

    fn friend_request(&self, to: UserId, event: &FriendshipEvent) {
        self.sent
            .lock()
            .unwrap()
            .push((Notice::FriendRequest, to, event.clone()));
    }
}

/// An activity handed to the federation port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sent {
    UndoFollow {
        from: ActorUri,
        to: ActorUri,
    },
    Reject {
        from: ActorUri,
        to: ActorUri,
        request: FriendshipId,
    },
    Follow {
        from: ActorUri,
        to: ActorUri,
    },
    Accept {
        from: ActorUri,
        to: ActorUri,
        request: FriendshipId,
        conversation: ConversationId,
    },
}

/// Records every activity, in order.
#[derive(Default)]
pub struct RecordingSocialFederation {
    sent: Mutex<Vec<Sent>>,
}

impl RecordingSocialFederation {
    pub fn sent(&self) -> Vec<Sent> {
        self.sent.lock().unwrap().clone()
    }
}

impl SocialFederation for RecordingSocialFederation {
    fn send_undo_follow(&self, from: &Account, to: &RemoteActor) {
        let sent = Sent::UndoFollow {
            from: from.actor_uri.clone(),
            to: to.actor_uri.clone(),
        };
        self.sent.lock().unwrap().push(sent);
    }

    fn send_reject(&self, from: &Account, to: &RemoteActor, request: FriendshipId) {
        let sent = Sent::Reject {
            from: from.actor_uri.clone(),
            to: to.actor_uri.clone(),
            request,
        };
        self.sent.lock().unwrap().push(sent);
    }

    fn send_accept(
        &self,
        from: &Account,
        to: &RemoteActor,
        request: FriendshipId,
        conversation: ConversationId,
    ) {
        let sent = Sent::Accept {
            from: from.actor_uri.clone(),
            to: to.actor_uri.clone(),
            request,
            conversation,
        };
        self.sent.lock().unwrap().push(sent);
    }

    fn send_follow(&self, from: &Account, to: &RemoteActor) {
        self.sent.lock().unwrap().push(Sent::Follow {
            from: from.actor_uri.clone(),
            to: to.actor_uri.clone(),
        });
    }
}

/// Records which friends' presence is watched and released.
#[derive(Default)]
pub struct RecordingFriendPresence {
    watched: Mutex<Vec<ActorUri>>,
    released: Mutex<Vec<ActorUri>>,
}

impl RecordingFriendPresence {
    pub fn watched(&self) -> Vec<ActorUri> {
        self.watched.lock().unwrap().clone()
    }

    pub fn released(&self) -> Vec<ActorUri> {
        self.released.lock().unwrap().clone()
    }
}

impl FriendPresence for RecordingFriendPresence {
    fn watch(&self, friend: &ActorUri) {
        self.watched.lock().unwrap().push(friend.clone());
    }

    fn release(&self, friend: &ActorUri) {
        self.released.lock().unwrap().push(friend.clone());
    }
}

#[async_trait::async_trait]
impl AccountEdits for InMemorySocialGraph {
    async fn save(&self, account: &Account) {
        if let Some(local) = self.locals.lock().unwrap().get_mut(&account.id) {
            local.display_name = account.display_name.clone();
            local.avatar_url = account.avatar_url.clone();
        }
    }
}

/// Run against the in-memory fake and the Postgres adapter. Each check takes accounts the graph
/// accepts — the Postgres ones are real `users` rows.
pub mod contract {
    use crate::ConversationId;
    use crate::identity::{Account, ActorUri};
    use crate::social::{Direction, FriendView, FriendshipStatus, SocialGraph, SocialStoreError};

    pub fn remote_bob() -> ActorUri {
        ActorUri::parse("https://idp.bob.test/users/bob_k2m9x").unwrap()
    }

    pub async fn an_outgoing_request_records_a_pending_outgoing_side(
        graph: &dyn SocialGraph,
        alice: &Account,
    ) {
        let side = graph
            .record_outgoing(alice.id, &remote_bob(), None)
            .await
            .unwrap();

        assert_eq!((side.owner, &side.friend), (alice.id, &remote_bob()));
        assert_eq!(
            (side.status, side.direction),
            (FriendshipStatus::Pending, Direction::Outgoing)
        );
        assert_eq!(
            graph.between(alice.id, &remote_bob()).await.unwrap(),
            Some(side)
        );
    }

    pub async fn a_new_request_takes_over_a_pending_side(
        graph: &dyn SocialGraph,
        alice: &Account,
        bob: &Account,
    ) {
        let first = graph.record_local_request(bob, alice).await.unwrap();

        let second = graph.record_local_request(alice, bob).await.unwrap();

        assert_eq!(
            second.requester_side.id, first.target_side.id,
            "alice keeps her one row"
        );
        assert_eq!(second.requester_side.direction, Direction::Outgoing);
        assert_eq!(second.target_side.direction, Direction::Incoming);
    }

    pub async fn accepting_makes_both_local_sides_friends_once(
        graph: &dyn SocialGraph,
        alice: &Account,
        bob: &Account,
    ) {
        let request = graph
            .record_local_request(alice, bob)
            .await
            .unwrap()
            .target_side;

        graph.accept(&request, bob).await.unwrap();

        for (owner, friend) in [(alice, bob), (bob, alice)] {
            let side = graph
                .between(owner.id, &friend.actor_uri)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                side.status,
                FriendshipStatus::Accepted,
                "{}'s side",
                owner.username
            );
        }
        let again = graph.accept(&request, bob).await;
        assert!(
            matches!(again, Err(SocialStoreError::Conflict)),
            "{again:?}"
        );
    }

    pub async fn declining_removes_both_local_sides(
        graph: &dyn SocialGraph,
        alice: &Account,
        bob: &Account,
    ) {
        let request = graph
            .record_local_request(alice, bob)
            .await
            .unwrap()
            .target_side;

        graph.decline(&request, bob).await.unwrap();

        assert_eq!(graph.between(bob.id, &alice.actor_uri).await.unwrap(), None);
        assert_eq!(graph.between(alice.id, &bob.actor_uri).await.unwrap(), None);
        let again = graph.decline(&request, bob).await;
        assert!(
            matches!(again, Err(SocialStoreError::Conflict)),
            "{again:?}"
        );
    }

    pub async fn unfriending_removes_both_local_sides(
        graph: &dyn SocialGraph,
        alice: &Account,
        bob: &Account,
    ) {
        let request = graph
            .record_local_request(alice, bob)
            .await
            .unwrap()
            .target_side;
        graph.accept(&request, bob).await.unwrap();
        assert!(graph.befriended_by_anyone(&bob.actor_uri).await.unwrap());

        let unfriended = graph
            .unfriend(alice, &bob.actor_uri)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(unfriended.removed.owner, alice.id);
        assert_eq!(unfriended.reverse.map(|side| side.id), Some(request.id));
        assert_eq!(graph.between(alice.id, &bob.actor_uri).await.unwrap(), None);
        assert_eq!(graph.between(bob.id, &alice.actor_uri).await.unwrap(), None);
        assert!(!graph.befriended_by_anyone(&bob.actor_uri).await.unwrap());
        assert_eq!(graph.unfriend(alice, &bob.actor_uri).await.unwrap(), None);
    }

    pub async fn the_dm_outlives_an_unfriend_and_is_reused(
        graph: &dyn SocialGraph,
        alice: &Account,
        bob: &Account,
    ) {
        let first = graph
            .record_local_request(alice, bob)
            .await
            .unwrap()
            .target_side;
        let dm = graph.accept(&first, bob).await.unwrap();
        graph.unfriend(alice, &bob.actor_uri).await.unwrap();

        let again = graph
            .record_local_request(alice, bob)
            .await
            .unwrap()
            .target_side;

        assert_eq!(graph.accept(&again, bob).await.unwrap(), dm);
    }

    pub async fn incoming_requests_are_the_pending_ones_received(
        graph: &dyn SocialGraph,
        alice: &Account,
        bob: &Account,
        pierre: &Account,
    ) {
        graph.record_local_request(alice, bob).await.unwrap();
        let from_pierre = graph
            .record_local_request(pierre, bob)
            .await
            .unwrap()
            .target_side;
        // Bob asking Alice in turn takes over her request: it becomes his own, outgoing.
        graph.record_local_request(bob, alice).await.unwrap();

        let incoming = graph.incoming_requests(bob.id).await.unwrap();

        let ids: Vec<_> = incoming.iter().map(|side| side.id).collect();
        assert_eq!(ids, vec![from_pierre.id]);
    }

    pub async fn the_friends_list_holds_accepted_friends_with_their_names(
        graph: &dyn SocialGraph,
        alice: &Account,
        bob: &Account,
        pierre: &Account,
    ) {
        let request = graph
            .record_local_request(bob, alice)
            .await
            .unwrap()
            .target_side;
        graph.accept(&request, alice).await.unwrap();
        graph.record_local_request(pierre, alice).await.unwrap();

        let friends = graph.friends(alice.id).await.unwrap();

        assert_eq!(
            friends,
            vec![FriendView {
                username: Some(bob.username.clone()),
                display_name: bob.display_name.clone(),
                avatar_url: None,
                actor_uri: bob.actor_uri.clone(),
                instance: "local".to_owned(),
            }]
        );
    }

    pub async fn a_local_friend_is_listed_as_it_now_is(
        graph: &dyn SocialGraph,
        edits: &dyn super::AccountEdits,
        alice: &Account,
        bob: &Account,
    ) {
        let bob = Account {
            avatar_url: Some("http://s3.test/avatars/bob.png?v=1".to_owned()),
            ..bob.clone()
        };
        edits.save(&bob).await;
        let request = graph
            .record_local_request(&bob, alice)
            .await
            .unwrap()
            .target_side;
        graph.accept(&request, alice).await.unwrap();
        let listed = |bob: &Account| {
            vec![FriendView {
                username: Some(bob.username.clone()),
                display_name: bob.display_name.clone(),
                avatar_url: bob.avatar_url.clone(),
                actor_uri: bob.actor_uri.clone(),
                instance: "local".to_owned(),
            }]
        };

        let renamed = Account {
            display_name: Some("Bob R.".to_owned()),
            avatar_url: Some("http://s3.test/avatars/bob.webp?v=2".to_owned()),
            ..bob
        };
        edits.save(&renamed).await;
        assert_eq!(graph.friends(alice.id).await.unwrap(), listed(&renamed));

        let bare = Account {
            avatar_url: None,
            ..renamed
        };
        edits.save(&bare).await;
        assert_eq!(graph.friends(alice.id).await.unwrap(), listed(&bare));
    }

    /// The friends list is compared on avatars only: a remote actor the store does not cache
    /// has no instance to show.
    pub async fn a_remote_friend_is_listed_with_the_avatar_it_was_met_with(
        graph: &dyn SocialGraph,
        alice: &Account,
        bob: &Account,
    ) {
        let met = "https://idp.bob.test/avatars/bob.png?v=1";
        graph
            .record_outgoing(alice.id, &remote_bob(), Some(met))
            .await
            .unwrap();
        graph
            .accept_outgoing(alice, &remote_bob(), None)
            .await
            .unwrap();
        let request = graph
            .record_incoming(bob.id, &remote_bob(), Some(met))
            .await
            .unwrap();
        graph.accept(&request, bob).await.unwrap();

        for owner in [alice, bob] {
            let avatars: Vec<_> = graph
                .friends(owner.id)
                .await
                .unwrap()
                .into_iter()
                .map(|friend| friend.avatar_url)
                .collect();
            assert_eq!(avatars, vec![Some(met.to_owned())], "{}", owner.username);
        }
    }

    pub async fn an_incoming_request_is_recorded_once_and_never_reopens_a_friendship(
        graph: &dyn SocialGraph,
        bob: &Account,
    ) {
        let first = graph
            .record_incoming(bob.id, &remote_bob(), None)
            .await
            .unwrap();
        let redelivered = graph
            .record_incoming(bob.id, &remote_bob(), None)
            .await
            .unwrap();
        assert_eq!(redelivered.id, first.id);
        assert_eq!(
            (first.status, first.direction),
            (FriendshipStatus::Pending, Direction::Incoming)
        );

        graph.accept(&first, bob).await.unwrap();
        let after_acceptance = graph
            .record_incoming(bob.id, &remote_bob(), None)
            .await
            .unwrap();

        assert_eq!(after_acceptance.status, FriendshipStatus::Accepted);
    }

    pub async fn an_accepted_outgoing_request_opens_the_advertised_dm_once(
        graph: &dyn SocialGraph,
        alice: &Account,
    ) {
        graph
            .record_outgoing(alice.id, &remote_bob(), None)
            .await
            .unwrap();
        let advertised = ConversationId::generate();

        let (side, dm) = graph
            .accept_outgoing(alice, &remote_bob(), Some(advertised))
            .await
            .unwrap()
            .expect("a pending outgoing request to accept");

        assert_eq!((side.status, dm), (FriendshipStatus::Accepted, advertised));
        assert_eq!(
            graph
                .dm_between(&alice.actor_uri, &remote_bob())
                .await
                .unwrap(),
            Some(dm)
        );
        let redelivered = graph
            .accept_outgoing(alice, &remote_bob(), Some(advertised))
            .await;
        assert_eq!(redelivered.unwrap(), None);
    }

    pub async fn an_advertised_id_naming_another_pairs_dm_opens_a_separate_one(
        graph: &dyn SocialGraph,
        alice: &Account,
        bob: &Account,
        carol: &Account,
    ) {
        let request = graph.record_local_request(carol, bob).await.unwrap();
        let theirs = graph.accept(&request.target_side, bob).await.unwrap();
        graph
            .record_outgoing(alice.id, &remote_bob(), None)
            .await
            .unwrap();

        let (_, dm) = graph
            .accept_outgoing(alice, &remote_bob(), Some(theirs))
            .await
            .unwrap()
            .expect("a pending outgoing request to accept");

        assert_ne!(dm, theirs);
        assert_eq!(
            graph
                .dm_between(&carol.actor_uri, &bob.actor_uri)
                .await
                .unwrap(),
            Some(theirs)
        );
    }

    pub async fn a_rejected_outgoing_request_is_dropped_once(
        graph: &dyn SocialGraph,
        alice: &Account,
    ) {
        graph
            .record_outgoing(alice.id, &remote_bob(), None)
            .await
            .unwrap();

        assert!(graph.drop_outgoing(alice.id, &remote_bob()).await.unwrap());

        assert_eq!(graph.between(alice.id, &remote_bob()).await.unwrap(), None);
        assert!(!graph.drop_outgoing(alice.id, &remote_bob()).await.unwrap());
        graph
            .record_incoming(alice.id, &remote_bob(), None)
            .await
            .unwrap();
        assert!(
            !graph.drop_outgoing(alice.id, &remote_bob()).await.unwrap(),
            "only a request alice sent"
        );
    }

    pub async fn a_local_request_records_both_sides_pending(
        graph: &dyn SocialGraph,
        alice: &Account,
        bob: &Account,
    ) {
        let recorded = graph.record_local_request(alice, bob).await.unwrap();

        let requester = &recorded.requester_side;
        assert_eq!(
            (requester.owner, &requester.friend),
            (alice.id, &bob.actor_uri)
        );
        assert_eq!(
            (requester.status, requester.direction),
            (FriendshipStatus::Pending, Direction::Outgoing)
        );
        let target = &recorded.target_side;
        assert_eq!((target.owner, &target.friend), (bob.id, &alice.actor_uri));
        assert_eq!(
            (target.status, target.direction),
            (FriendshipStatus::Pending, Direction::Incoming)
        );
        assert_eq!(
            graph
                .between(alice.id, &bob.actor_uri)
                .await
                .unwrap()
                .as_ref(),
            Some(requester)
        );
        assert_eq!(
            graph
                .between(bob.id, &alice.actor_uri)
                .await
                .unwrap()
                .as_ref(),
            Some(target)
        );
    }
}

#[cfg(test)]
mod tests;
