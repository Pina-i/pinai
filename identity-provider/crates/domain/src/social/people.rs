use crate::FriendshipId;
use crate::identity::{ActorUri, FederatedAddress};

use super::{Direction, Friendship, FriendshipStatus};

/// How someone stands with an account, from the account's side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standing {
    /// The account blocked them.
    Blocked,
    Friend,
    /// They asked the account to be friends; the account answers through this side.
    RequestReceived(FriendshipId),
    RequestSent,
    Unrelated,
}

/// What an account's instance holds of its ties to someone, read with them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ties {
    /// The account blocked them.
    pub blocked: bool,
    /// The account's side of a friendship or a request with them.
    pub side: Option<Friendship>,
}

impl Ties {
    /// The first that holds: a block, a friendship, a request received, a request sent. A block
    /// the other made is not the account's to know: it never shows.
    pub fn standing(&self) -> Standing {
        if self.blocked {
            return Standing::Blocked;
        }
        match &self.side {
            Some(side) if side.status == FriendshipStatus::Accepted => Standing::Friend,
            Some(side) if side.direction == Direction::Incoming => {
                Standing::RequestReceived(side.id)
            }
            Some(_) => Standing::RequestSent,
            None => Standing::Unrelated,
        }
    }
}

/// Someone a search or a lookup found, with the caller's ties to them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundPerson {
    pub actor: ActorUri,
    pub address: FederatedAddress,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub ties: Ties,
}

/// Someone of another instance the caller shares a group with, and the name of the latest group
/// they share — `None` when it has none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupPerson {
    pub person: FoundPerson,
    pub group: Option<String>,
}

/// What a search by name finds: this instance's accounts, and the people of the caller's groups
/// elsewhere.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeopleFound {
    pub server: Vec<FoundPerson>,
    pub groups: Vec<GroupPerson>,
}

#[cfg(test)]
mod tests;
