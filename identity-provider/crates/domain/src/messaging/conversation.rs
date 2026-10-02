use time::OffsetDateTime;

use super::group::MAX_MEMBERS;
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
    /// When the name was last set, wherever that was.
    pub name_at: OffsetDateTime,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub actor_uri: ActorUri,
    pub role: Role,
}

/// A membership ever held, with the stamps of its last changes. Each stamp is set where the change
/// was made and copied as is, so every instance's copy of a group orders changes the same way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Membership {
    pub member: Member,
    pub joined_at: OffsetDateTime,
    pub role_at: OffsetDateTime,
    /// `None` while the member is in the group.
    pub left_at: Option<OffsetDateTime>,
}

impl Membership {
    pub fn is_active(&self) -> bool {
        self.left_at.is_none()
    }
}

/// How a member came to be out of a group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Departure {
    pub left_at: OffsetDateTime,
    /// The admin who removed them; `None` when they left.
    pub removed_by: Option<ActorUri>,
    /// They cleared the group from their list.
    pub dismissed: bool,
}

impl Departure {
    /// Up to when a former member still reads the group: one who was removed keeps it as it
    /// stood, until they clear it; one who left keeps nothing.
    pub fn reads_until(&self) -> Option<OffsetDateTime> {
        (self.removed_by.is_some() && !self.dismissed).then_some(self.left_at)
    }
}

/// A member as a snapshot lists them. The stamps are `None` from an instance that predates them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotMember {
    pub member: Member,
    pub joined_at: Option<OffsetDateTime>,
    pub role_at: Option<OffsetDateTime>,
}

/// A group as the instance that sent a message sees it. Every group message carries one, so a
/// member whose Welcome never arrived still gets the conversation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupSnapshot {
    pub name: Option<String>,
    pub name_at: Option<OffsetDateTime>,
    /// The active members only: an absence says nothing, a departure travels on its own.
    pub members: Vec<SnapshotMember>,
}

/// A group's name with the time it was set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StampedName {
    pub name: Option<String>,
    pub at: OffsetDateTime,
}

/// What a copy of a group takes from a snapshot.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GroupChanges {
    /// Always set for a group new here.
    pub name: Option<StampedName>,
    /// Each to be held active, exactly as given.
    pub members: Vec<Membership>,
}

impl GroupChanges {
    pub fn is_empty(&self) -> bool {
        self.name.is_none() && self.members.is_empty()
    }
}

/// A copy of a group once changes are taken, and the members taking them brought in: added, or
/// back from a departure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mirrored {
    pub group: Conversation,
    pub brought_in: Vec<ActorUri>,
}

impl GroupSnapshot {
    /// The group as this instance holds it, every stamp included.
    pub fn of(group: &Conversation, held: &[Membership]) -> Self {
        Self {
            name: group.name.clone(),
            name_at: Some(group.name_at),
            members: held
                .iter()
                .filter(|m| m.is_active())
                .map(|m| SnapshotMember {
                    member: m.member.clone(),
                    joined_at: Some(m.joined_at),
                    role_at: Some(m.role_at),
                })
                .collect(),
        }
    }

    /// What a copy holding `local` and `held` takes from this snapshot: per field, the newer
    /// stamp wins. So a stale snapshot never brings back a member who left, nor undoes a rename
    /// or a role change, whatever order snapshots arrive in. `now` stamps what an unstamped
    /// snapshot adds. Newcomers are taken only while the copy holds fewer than `MAX_MEMBERS`.
    pub fn changes(
        &self,
        local: Option<&Conversation>,
        held: &[Membership],
        now: OffsetDateTime,
    ) -> GroupChanges {
        let name = match local {
            None => Some(StampedName {
                name: self.name.clone(),
                at: self.name_at.unwrap_or(now),
            }),
            Some(group) => self
                .name_at
                .filter(|at| *at > group.name_at)
                .map(|at| StampedName {
                    name: self.name.clone(),
                    at,
                }),
        };
        let mut room = MAX_MEMBERS.saturating_sub(held.iter().filter(|m| m.is_active()).count());
        let members = self
            .members
            .iter()
            .filter_map(|entry| {
                let mine = held
                    .iter()
                    .find(|m| m.member.actor_uri == entry.member.actor_uri);
                let change = entry.applied_to(mine, now)?;
                if mine.is_none_or(|m| !m.is_active()) {
                    room = room.checked_sub(1)?;
                }
                Some(change)
            })
            .collect();
        GroupChanges { name, members }
    }

    /// Whether `sender` may assert this roster: a member of the group as this instance knows it,
    /// or — for a group new here — one the snapshot itself lists. A DM never takes a roster.
    pub fn may_be_asserted_by(
        &self,
        sender: &ActorUri,
        local: Option<&Conversation>,
        members: &[Member],
    ) -> bool {
        match local {
            None => self.members.iter().any(|m| &m.member.actor_uri == sender),
            Some(group) if group.kind == ConversationKind::Group => {
                members.iter().any(|m| &m.actor_uri == sender)
            }
            Some(_) => false,
        }
    }

    /// Who the group is announced as created by: its first admin, else the message's sender.
    pub fn creator<'a>(&'a self, sender: &'a ActorUri) -> &'a ActorUri {
        self.members
            .iter()
            .find(|m| m.member.role == Role::Admin)
            .map_or(sender, |m| &m.member.actor_uri)
    }
}

impl SnapshotMember {
    /// The membership a copy holding `held` takes from this entry, when it changes anything.
    fn applied_to(&self, held: Option<&Membership>, now: OffsetDateTime) -> Option<Membership> {
        let Some(held) = held else {
            let joined_at = self.joined_at.unwrap_or(now);
            return Some(Membership {
                member: self.member.clone(),
                joined_at,
                role_at: self.role_at.unwrap_or(joined_at),
                left_at: None,
            });
        };
        if let Some(left_at) = held.left_at {
            let joined_at = self.joined_at.filter(|at| *at > left_at)?;
            return Some(Membership {
                member: self.member.clone(),
                joined_at,
                role_at: self.role_at.unwrap_or(joined_at),
                left_at: None,
            });
        }
        let joined_at = self.joined_at.filter(|at| *at > held.joined_at);
        let role_at = self.role_at.filter(|at| *at > held.role_at);
        if joined_at.is_none() && role_at.is_none() {
            return None;
        }
        Some(Membership {
            member: Member {
                actor_uri: held.member.actor_uri.clone(),
                role: if role_at.is_some() {
                    self.member.role
                } else {
                    held.member.role
                },
            },
            joined_at: joined_at.unwrap_or(held.joined_at),
            role_at: role_at.unwrap_or(held.role_at),
            left_at: None,
        })
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
    /// When the account was removed from the group. Its name, members and last message are
    /// then as they stood at that moment, and nothing counts as unread.
    pub removed_at: Option<OffsetDateTime>,
}

#[cfg(test)]
mod tests;
