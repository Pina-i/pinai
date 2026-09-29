use crate::identity::{Account, ActorUri, RemoteActor};
use crate::{ConversationId, FriendshipId, UserId};

use super::Friendship;

/// The friend graph. Each method is one business operation, atomic on its own.
#[async_trait::async_trait]
pub trait SocialGraph: Send + Sync {
    /// Both sides of a request between two local accounts, `pending`: the requester's `outgoing`,
    /// the target's `incoming`. A side already accepted is left as it is.
    async fn record_local_request(
        &self,
        requester: &Account,
        target: &Account,
    ) -> Result<LocalRequest, SocialStoreError>;

    /// The owner's `outgoing` side of a request to a remote actor, `pending` — the peer's IdP
    /// holds the other side. An accepted side is left as it is.
    async fn record_outgoing(
        &self,
        owner: UserId,
        friend: &ActorUri,
        friend_avatar_url: Option<&str>,
    ) -> Result<Friendship, SocialStoreError>;

    /// Accept a pending incoming request: the accepter's side and — when the requester is local —
    /// theirs become `accepted`, and the DM between the two is opened, or reused if they had one.
    /// `Conflict` when the request is no longer pending (accepted meanwhile, or withdrawn).
    async fn accept(
        &self,
        request: &Friendship,
        accepter: &Account,
    ) -> Result<ConversationId, SocialStoreError>;

    /// Decline a pending incoming request: the decliner's side and — when the requester is local —
    /// theirs are removed together. `Conflict` when the request is no longer pending.
    async fn decline(
        &self,
        request: &Friendship,
        decliner: &Account,
    ) -> Result<(), SocialStoreError>;

    /// End the owner's side of a friendship — or withdraw a request they sent — and, when the
    /// friend is local, the friend's side with it. The DM conversation is kept. `None` when the
    /// owner had no side.
    async fn unfriend(
        &self,
        owner: &Account,
        friend: &ActorUri,
    ) -> Result<Option<Unfriended>, SocialStoreError>;

    /// Whether any local account still has `friend` as an accepted friend.
    async fn befriended_by_anyone(&self, friend: &ActorUri) -> Result<bool, SocialStoreError>;

    /// The pending requests the owner received, newest first.
    async fn incoming_requests(&self, owner: UserId) -> Result<Vec<Friendship>, SocialStoreError>;

    /// The owner's accepted friends, local and remote, with what is known of their names.
    async fn friends(&self, owner: UserId) -> Result<Vec<FriendView>, SocialStoreError>;

    /// The owner's `incoming` side of a request a remote actor sent, `pending`. A redelivered
    /// request keeps the one side; an accepted side is left as it is.
    async fn record_incoming(
        &self,
        owner: UserId,
        friend: &ActorUri,
    ) -> Result<Friendship, SocialStoreError>;

    /// A remote actor accepted the owner's pending outgoing request: it becomes `accepted` and the
    /// DM is opened — under `advertised`, the id the peer chose, unless the two already share one.
    /// `None` when there is no such pending request (already accepted: a redelivery).
    async fn accept_outgoing(
        &self,
        owner: &Account,
        accepter: &ActorUri,
        advertised: Option<ConversationId>,
    ) -> Result<Option<(Friendship, ConversationId)>, SocialStoreError>;

    /// A remote actor declined the owner's pending outgoing request. `false` when there was none.
    async fn drop_outgoing(
        &self,
        owner: UserId,
        friend: &ActorUri,
    ) -> Result<bool, SocialStoreError>;

    /// The DM the two actors share, if any.
    async fn dm_between(
        &self,
        a: &ActorUri,
        b: &ActorUri,
    ) -> Result<Option<ConversationId>, SocialStoreError>;

    async fn find(&self, id: FriendshipId) -> Result<Option<Friendship>, SocialStoreError>;

    /// The owner's side of the friendship with `friend`, if there is one.
    async fn between(
        &self,
        owner: UserId,
        friend: &ActorUri,
    ) -> Result<Option<Friendship>, SocialStoreError>;
}

/// Tells a local account's live sessions what happened to one of its friendships.
pub trait SocialNotifier: Send + Sync {
    fn friend_request(&self, to: UserId, event: &FriendshipEvent);
    fn friend_accepted(&self, to: UserId, event: &FriendshipEvent);
    fn friend_removed(&self, to: UserId, event: &FriendshipEvent);
}

/// The friendship activities sent to other instances. Fire-and-forget: each is delivered after the
/// local change is committed, and a peer that cannot be reached never fails the request — the
/// adapter logs the failure where it happens.
pub trait SocialFederation: Send + Sync {
    fn send_follow(&self, from: &Account, to: &RemoteActor);
    /// Withdraw the friendship (or the request) on the peer's side.
    fn send_undo_follow(&self, from: &Account, to: &RemoteActor);
    /// The refusal of the Follow behind `request`.
    fn send_reject(&self, from: &Account, to: &RemoteActor, request: FriendshipId);
    /// The answer to the Follow behind `request`, naming the DM so both instances file it under
    /// the same id.
    fn send_accept(
        &self,
        from: &Account,
        to: &RemoteActor,
        request: FriendshipId,
        conversation: ConversationId,
    );
}

/// Following a friend's presence on another instance.
pub trait FriendPresence: Send + Sync {
    fn watch(&self, friend: &ActorUri);
    fn release(&self, friend: &ActorUri);
}

/// What the account's clients are told: the friendship (their side), and who is on the other end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FriendshipEvent {
    pub friendship: FriendshipId,
    pub actor_uri: ActorUri,
    pub username: String,
    pub display_name: Option<String>,
    /// The DM conversation, on acceptance only.
    pub conversation: Option<ConversationId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalRequest {
    pub requester_side: Friendship,
    pub target_side: Friendship,
}

/// One entry of a friends list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FriendView {
    /// Local friends only.
    pub username: Option<String>,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub actor_uri: ActorUri,
    /// The friend's instance, or `local`.
    pub instance: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unfriended {
    /// The owner's side, as it was.
    pub removed: Friendship,
    /// The local friend's side, removed with it.
    pub reverse: Option<Friendship>,
}

#[derive(Debug, thiserror::Error)]
pub enum SocialStoreError {
    #[error("the friendship changed meanwhile")]
    Conflict,
    #[error(transparent)]
    Unexpected(#[from] anyhow::Error),
}
