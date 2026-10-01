use time::OffsetDateTime;

use crate::identity::ActorUri;

use super::{Direction, Friendship, FriendshipStatus, SocialError};

/// An actor the owner blocked, with what is known of their name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockedActor {
    pub actor: ActorUri,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub blocked_at: OffsetDateTime,
}

/// What a block makes of the friendship the blocker had: it ends as the matching friendship
/// action would, so the blocked account meets an unfriend or a decline, never a block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ending {
    /// A friendship, or a request the blocker sent: withdrawn, as by an unfriend.
    Unfriend,
    /// A request the blocked account sent: declined.
    Decline,
}

impl Ending {
    /// From the blocker's side, as it was.
    pub fn of(side: &Friendship) -> Self {
        match (side.status, side.direction) {
            (FriendshipStatus::Pending, Direction::Incoming) => Self::Decline,
            _ => Self::Unfriend,
        }
    }
}

/// How many actors one account may block: the list is stored as its owner writes it.
pub const MAX_BLOCKS: usize = 1_000;

/// Whether `actor` may join the list. Blocking again changes nothing, so a full list takes an actor
/// already on it.
pub fn room_for(blocked: &[BlockedActor], actor: &ActorUri) -> Result<(), SocialError> {
    if blocked.len() >= MAX_BLOCKS && !blocked.iter().any(|b| &b.actor == actor) {
        return Err(SocialError::BlockListFull);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
