use std::fmt;

use time::{Duration, OffsetDateTime};

use crate::identity::ActorUri;
use crate::messaging::Member;
use crate::{CommitId, ConversationId, DeviceId, UserId, ValidationError, WelcomeId};

use super::DeliveryError;

/// How many commits one catch-up page holds.
pub const CATCH_UP_LIMIT: usize = 256;

/// How long a claimed Welcome is kept before it is deleted: a flaky re-fetch then reads an
/// empty list, never the same bundle twice.
pub const CLAIMED_WELCOME_GRACE: Duration = Duration::days(1);

/// A commit's place in its group's history.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Epoch(i64);

impl Epoch {
    pub fn parse(epoch: i64) -> Result<Self, ValidationError> {
        if epoch < 0 {
            return Err(ValidationError::new("epoch", "must be non-negative"));
        }
        Ok(Self(epoch))
    }

    pub fn value(self) -> i64 {
        self.0
    }
}

macro_rules! blob {
    ($name:ident, $field:literal, $what:literal) => {
        #[doc = $what]
        #[derive(Clone, PartialEq, Eq)]
        pub struct $name(Vec<u8>);

        impl $name {
            pub fn parse(bytes: Vec<u8>) -> Result<Self, ValidationError> {
                if bytes.is_empty() {
                    return Err(ValidationError::new($field, "is empty"));
                }
                Ok(Self(bytes))
            }

            pub fn as_bytes(&self) -> &[u8] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({} bytes)", stringify!($name), self.0.len())
            }
        }
    };
}

blob!(
    CommitBlob,
    "commit_blob",
    "A TLS-encoded MLS Commit: opaque here, never empty."
);
blob!(
    WelcomeBlob,
    "welcome_blob",
    "A TLS-encoded MLS Welcome: opaque here, never empty."
);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commit {
    pub id: CommitId,
    pub conversation: ConversationId,
    pub epoch: Epoch,
    pub blob: CommitBlob,
    pub proposer: ActorUri,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewCommit {
    pub conversation: ConversationId,
    pub epoch: Epoch,
    pub blob: CommitBlob,
    pub proposer: ActorUri,
}

/// A commit's fate: stored, or beaten to its epoch by the one returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Append {
    Stored(Commit),
    Taken(Commit),
}

/// A Welcome waiting for the device it admits to a group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Welcome {
    pub id: WelcomeId,
    pub recipient: UserId,
    pub device: DeviceId,
    pub conversation: ConversationId,
    pub blob: WelcomeBlob,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewWelcome {
    pub recipient: UserId,
    pub device: DeviceId,
    pub conversation: ConversationId,
    pub blob: WelcomeBlob,
}

/// Only a conversation's active members commit to its MLS group.
pub fn may_commit(members: &[Member], proposer: &ActorUri) -> bool {
    members.iter().any(|m| &m.actor_uri == proposer)
}

/// A Welcome admits a device of one member, handed out by another — it never makes anyone a
/// member: joining is the group routes' business, with their admin rules.
pub fn check_welcome(
    members: &[Member],
    sender: &ActorUri,
    recipient: &ActorUri,
) -> Result<(), DeliveryError> {
    let is_member = |actor: &ActorUri| members.iter().any(|m| &m.actor_uri == actor);
    if !is_member(sender) {
        return Err(DeliveryError::NotAMember);
    }
    if !is_member(recipient) {
        return Err(DeliveryError::RecipientNotAMember);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
