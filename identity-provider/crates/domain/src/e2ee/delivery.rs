use std::fmt;

use time::{Duration, OffsetDateTime};

use crate::identity::ActorUri;
use crate::messaging::Member;
use crate::{CommitId, ConversationId, DeviceId, UserId, ValidationError, WelcomeId};

use super::{DeliveryError, DeviceTrust, may_act_beyond_the_password, sessions_device};

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

    /// The epoch a member's commit takes: right after the log's latest, 1 for a group's first.
    pub fn after(latest: Option<Self>) -> Self {
        Self(latest.map_or(1, |latest| latest.0.saturating_add(1)))
    }

    /// Only the epoch right after the log's latest is appended by a member: past it, the log
    /// would hold a gap no member can catch up through; below it, an epoch the members applied
    /// differently.
    pub fn follows(self, latest: Option<Self>) -> bool {
        self == Self::after(latest)
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
blob!(
    GroupInfoBlob,
    "group_info",
    "A TLS-encoded MLS GroupInfo: opaque here, never empty."
);

/// RFC 9420 § 6: the protocol version `mls10`, the `WireFormat`s of a `PublicMessage` and a
/// `PrivateMessage`, the `SenderType` of a device committing itself into the group, and the
/// `ContentType` of a commit.
const MLS10: u16 = 1;
const PUBLIC_MESSAGE: u16 = 1;
const PRIVATE_MESSAGE: u16 = 2;
const NEW_MEMBER_COMMIT: u8 = 4;
const COMMIT: u8 = 3;

/// The two commits the Delivery Service takes, told apart by their clear header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitKind {
    /// A member's: a `PrivateMessage` whose content is a commit — a group's members send nothing
    /// in the clear.
    Member,
    /// A device committing itself in — an external commit (RFC 9420 § 12.4.3.2): a
    /// `PublicMessage` from a `new_member_commit` sender.
    External,
}

impl CommitBlob {
    /// `None` for anything else — a `PublicMessage` from another sender, a join proposal among
    /// them, a `PrivateMessage` carrying no commit, another wire format or version, bytes cut
    /// short —, which no member's device may be handed as a commit.
    pub fn kind(&self) -> Option<CommitKind> {
        commit_kind(&self.0)
    }
}

/// `MLSMessage { uint16 version; uint16 wire_format; … }`, then, in both a `PublicMessage`'s
/// `FramedContent` and a `PrivateMessage`, `opaque group_id<V>; uint64 epoch;` — followed by the
/// sender's `uint8 sender_type` in the first, the `uint8 content_type` in the second.
fn commit_kind(message: &[u8]) -> Option<CommitKind> {
    let field = |at: usize| {
        Some(u16::from_be_bytes([
            *message.get(at)?,
            *message.get(at + 1)?,
        ]))
    };
    let (version, wire_format) = (field(0)?, field(2)?);
    let (group_id, rest) = vector_length(message.get(4..)?)?;
    let epoch = 8;
    let next = *rest.get(group_id.checked_add(epoch)?)?;
    match (version, wire_format, next) {
        (MLS10, PUBLIC_MESSAGE, NEW_MEMBER_COMMIT) => Some(CommitKind::External),
        (MLS10, PRIVATE_MESSAGE, COMMIT) => Some(CommitKind::Member),
        _ => None,
    }
}

/// A variable-length vector's length and what follows it (RFC 9420 § 2.1.2): the top two bits of
/// the first byte say the length takes 1, 2 or 4 bytes; `11` is invalid.
fn vector_length(bytes: &[u8]) -> Option<(usize, &[u8])> {
    let first = *bytes.first()?;
    let size = match first >> 6 {
        0 => 1,
        1 => 2,
        2 => 4,
        _ => return None,
    };
    let length = bytes
        .get(1..size)?
        .iter()
        .fold(u32::from(first & 0x3f), |length, byte| {
            length << 8 | u32::from(*byte)
        });
    Some((usize::try_from(length).ok()?, &bytes[size..]))
}

/// The GroupInfo of the epoch a commit opened: what a device joins the group by on its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupInfo {
    pub epoch: Epoch,
    pub blob: GroupInfoBlob,
}

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

/// Whether a session whose device is `named` may commit that device into a group by itself — an
/// external commit, [`CommitKind::External`]: a session that named its device, approved under
/// the account's current generation ([`may_act_beyond_the_password`]). Someone with only the
/// password must not join the user's conversations.
pub fn may_commit_externally(
    named: Option<DeviceId>,
    trust: &DeviceTrust,
) -> Result<(), DeliveryError> {
    sessions_device(named)?;
    Ok(may_act_beyond_the_password(named, trust)?)
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
