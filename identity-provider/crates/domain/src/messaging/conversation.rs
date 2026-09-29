use time::OffsetDateTime;

use crate::identity::ActorUri;
use crate::{ConversationId, ValidationError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConversationKind {
    Dm,
    Group,
}

/// A member's standing in a group; both members of a DM are `Member`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Admin,
    Member,
}

impl ConversationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dm => "dm",
            Self::Group => "group",
        }
    }
}

impl std::str::FromStr for ConversationKind {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "dm" => Ok(Self::Dm),
            "group" => Ok(Self::Group),
            other => Err(ValidationError::new(
                "conversation kind",
                format!("unknown value {other:?}"),
            )),
        }
    }
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Member => "member",
        }
    }
}

impl std::str::FromStr for Role {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "admin" => Ok(Self::Admin),
            "member" => Ok(Self::Member),
            other => Err(ValidationError::new(
                "role",
                format!("unknown value {other:?}"),
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conversation {
    pub id: ConversationId,
    pub kind: ConversationKind,
    pub name: Option<String>,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub actor_uri: ActorUri,
    pub role: Role,
}

/// A group as the instance that sent a message sees it. Every group message carries one, so a
/// member whose Welcome never arrived still gets the conversation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupSnapshot {
    pub name: Option<String>,
    pub members: Vec<Member>,
}

impl GroupSnapshot {
    /// Whether the local copy already holds the snapshot: every member in its role, and its name.
    /// Additive only — a local member the snapshot lacks is left alone, since the sender's copy
    /// may be the stale one; removals are enforced by the MLS Remove commit.
    pub fn is_mirrored_by(&self, local: Option<&Conversation>, members: &[Member]) -> bool {
        let Some(local) = local else {
            return false;
        };
        let renamed = self
            .name
            .as_deref()
            .is_some_and(|name| local.name.as_deref() != Some(name));
        !renamed && self.members.iter().all(|m| members.contains(m))
    }

    /// Whether `sender` may assert this roster: a member of the group as this instance knows it,
    /// or — for a group new here — one the snapshot itself lists. A DM never takes a roster.
    pub fn may_be_asserted_by(
        &self,
        sender: &ActorUri,
        local: Option<&Conversation>,
        members: &[Member],
    ) -> bool {
        let lists = |members: &[Member]| members.iter().any(|m| &m.actor_uri == sender);
        match local {
            None => lists(&self.members),
            Some(group) if group.kind == ConversationKind::Group => lists(members),
            Some(_) => false,
        }
    }

    /// Who the group is announced as created by: its first admin, else the message's sender.
    pub fn creator<'a>(&'a self, sender: &'a ActorUri) -> &'a ActorUri {
        self.members
            .iter()
            .find(|m| m.role == Role::Admin)
            .map_or(sender, |m| &m.actor_uri)
    }
}

/// Whether a conversation that already exists under an id a client or a peer chose may file the
/// DM of `a` and `b`: only a DM none but the two ever belonged to. Any other would add the pair
/// to someone else's conversation.
pub fn may_hold_dm(
    kind: ConversationKind,
    members: &[ActorUri],
    a: &ActorUri,
    b: &ActorUri,
) -> bool {
    kind == ConversationKind::Dm && members.iter().all(|m| m == a || m == b)
}

/// Another member of a conversation, as a conversation list shows them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberView {
    pub actor_uri: ActorUri,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
}

/// One row of an account's conversation list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversationSummary {
    pub id: ConversationId,
    pub kind: ConversationKind,
    pub name: Option<String>,
    /// Every active member but the account itself.
    pub members: Vec<MemberView>,
    pub last_message_sender: Option<ActorUri>,
    /// Messages from others since the account last read the conversation.
    pub unread_count: i64,
    pub last_message_at: Option<OffsetDateTime>,
}

#[cfg(test)]
mod tests;
