use crate::identity::ActorUri;
use crate::{FriendshipId, UserId, ValidationError};

use super::SocialError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FriendshipStatus {
    Pending,
    Accepted,
}

/// Which side of the request the owner is on: they sent it, or they received it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Outgoing,
    Incoming,
}

impl FriendshipStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
        }
    }
}

impl std::str::FromStr for FriendshipStatus {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pending" => Ok(Self::Pending),
            "accepted" => Ok(Self::Accepted),
            other => Err(ValidationError::new(
                "friendship status",
                format!("unknown value {other:?}"),
            )),
        }
    }
}

impl Direction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Outgoing => "outgoing",
            Self::Incoming => "incoming",
        }
    }
}

impl std::str::FromStr for Direction {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "outgoing" => Ok(Self::Outgoing),
            "incoming" => Ok(Self::Incoming),
            other => Err(ValidationError::new(
                "friendship direction",
                format!("unknown value {other:?}"),
            )),
        }
    }
}

/// One side of a friendship, owned by a local account. Each side has its own row — both on this
/// instance for a local pair, one on each instance for a federated one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Friendship {
    pub id: FriendshipId,
    pub owner: UserId,
    pub friend: ActorUri,
    pub status: FriendshipStatus,
    pub direction: Direction,
}

impl Friendship {
    /// A new request may replace a pending one — the latest request decides who answers — but an
    /// accepted friendship is never taken back to pending; it ends through unfriend only.
    pub fn requestable(existing: Option<&Friendship>) -> Result<(), SocialError> {
        match existing {
            Some(f) if f.status == FriendshipStatus::Accepted => Err(SocialError::AlreadyFriends),
            _ => Ok(()),
        }
    }

    /// Only the side that received a still-pending request may accept or decline it: accepting
    /// one's own request would form the friendship without the other side consenting.
    pub fn answerable_by(&self, user: UserId) -> Result<(), SocialError> {
        if self.owner != user {
            return Err(SocialError::NotYours);
        }
        if self.status != FriendshipStatus::Pending || self.direction != Direction::Incoming {
            return Err(SocialError::NotAnIncomingRequest);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
