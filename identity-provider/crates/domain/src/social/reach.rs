use crate::ValidationError;

/// Who may message an account or add it to a group, as its owner chose. The default makes an
/// unfriend already stop the DMs, which is what lets a block pass for one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ContactPolicy {
    Everyone,
    #[default]
    FriendsAndGroups,
    Friends,
}

impl ContactPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Everyone => "everyone",
            Self::FriendsAndGroups => "friends_and_groups",
            Self::Friends => "friends",
        }
    }
}

impl std::str::FromStr for ContactPolicy {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "everyone" => Ok(Self::Everyone),
            "friends_and_groups" => Ok(Self::FriendsAndGroups),
            "friends" => Ok(Self::Friends),
            other => Err(ValidationError::new(
                "contact policy",
                format!("unknown value {other:?}"),
            )),
        }
    }
}

/// What an account's instance holds of the account's ties to another actor, read together.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Relation {
    /// The account's contact setting.
    pub policy: ContactPolicy,
    /// The account blocked the other actor.
    pub blocked: bool,
    /// An accepted friendship.
    pub friends: bool,
    /// Both are active members of a group.
    pub share_a_group: bool,
}

impl Relation {
    /// Whether the other actor may message the account or add it to a group. A block wins over
    /// everything; the 1:1 DM the two may keep is no tie.
    pub fn admits(&self) -> Result<(), Unreachable> {
        let admitted = !self.blocked
            && match self.policy {
                ContactPolicy::Everyone => true,
                ContactPolicy::FriendsAndGroups => self.friends || self.share_a_group,
                ContactPolicy::Friends => self.friends,
            };
        admitted.then_some(()).ok_or(Unreachable)
    }

    /// Whether the account may write to the other actor: not while it blocks them.
    pub fn may_write(&self) -> Result<(), YouBlocked> {
        (!self.blocked).then_some(()).ok_or(YouBlocked)
    }

    /// Whether a group new to the account may be mirrored for it off a message the other actor
    /// sent in it. The roster doesn't say who added whom, so it falls back to its members.
    pub fn admits_group_from(&self, roster_holds_someone_blocked: bool) -> Result<(), Unreachable> {
        if roster_holds_someone_blocked {
            return Err(Unreachable);
        }
        self.admits()
    }

    /// Whether the account hears of a friend request from the other actor. The contact setting
    /// doesn't cover requests: only a block keeps one out, and the requester just sees it go
    /// unanswered.
    pub fn hears_requests(&self) -> bool {
        !self.blocked
    }
}

/// The account can't be reached by that actor. Whether a block or the contact setting kept them
/// out is never told: the blocked person must not tell one from the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the account cannot be reached")]
pub struct Unreachable;

/// The account writes to someone it blocked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the account blocked the actor it writes to")]
pub struct YouBlocked;

#[cfg(test)]
mod tests;
