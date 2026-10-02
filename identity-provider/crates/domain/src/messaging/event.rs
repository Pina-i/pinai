use time::OffsetDateTime;

use super::conversation::{Departure, Membership, Role};
use super::group_change::{GroupChange, GroupChangeKind};
use crate::identity::ActorUri;
use crate::{ConversationId, GroupEventId};

/// A change to a group as its conversation shows it, between the messages —
/// identity-provider/specs/groups.md § 6.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupEvent {
    pub id: GroupEventId,
    pub group: ConversationId,
    /// Who made the change.
    pub by: ActorUri,
    /// The change's stamp, so the event sits where the change happened among the messages.
    pub at: OffsetDateTime,
    pub kind: GroupEventKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupEventKind {
    Created,
    Changed(GroupChangeKind),
}

impl GroupEvent {
    pub fn created(group: ConversationId, by: ActorUri, at: OffsetDateTime) -> Self {
        Self {
            id: GroupEventId::generate(),
            group,
            by,
            at,
            kind: GroupEventKind::Created,
        }
    }

    pub fn of(change: &GroupChange) -> Self {
        Self {
            id: GroupEventId::generate(),
            group: change.group,
            by: change.by.clone(),
            at: change.at,
            kind: GroupEventKind::Changed(change.kind.clone()),
        }
    }

    /// What happened, as the store and the clients name it.
    pub fn kind_name(&self) -> &'static str {
        match &self.kind {
            GroupEventKind::Created => "created",
            GroupEventKind::Changed(GroupChangeKind::Added(_)) => "added",
            GroupEventKind::Changed(GroupChangeKind::Removed(_)) => "removed",
            GroupEventKind::Changed(GroupChangeKind::Left) => "left",
            GroupEventKind::Changed(GroupChangeKind::Renamed(_)) => "renamed",
            GroupEventKind::Changed(GroupChangeKind::RoleChanged(..)) => "role_changed",
        }
    }

    /// The group's new name, for a rename.
    pub fn name(&self) -> Option<&str> {
        match &self.kind {
            GroupEventKind::Changed(GroupChangeKind::Renamed(name)) => Some(name.as_str()),
            _ => None,
        }
    }

    /// The member's new role, for a role change.
    pub fn role(&self) -> Option<Role> {
        match &self.kind {
            GroupEventKind::Changed(GroupChangeKind::RoleChanged(_, role)) => Some(*role),
            _ => None,
        }
    }

    /// The member it is about: the one added, removed or given a role, or the one leaving.
    pub fn subject(&self) -> Option<&ActorUri> {
        match &self.kind {
            GroupEventKind::Created | GroupEventKind::Changed(GroupChangeKind::Renamed(_)) => None,
            GroupEventKind::Changed(GroupChangeKind::Left) => Some(&self.by),
            GroupEventKind::Changed(
                GroupChangeKind::Added(member)
                | GroupChangeKind::Removed(member)
                | GroupChangeKind::RoleChanged(member, _),
            ) => Some(member),
        }
    }
}

/// The span of a conversation's events a reader sees: from their latest join on, so nobody learns
/// what happened in a group before they were in it, and up to their removal once removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventWindow {
    pub since: OffsetDateTime,
    pub until: Option<OffsetDateTime>,
}

impl EventWindow {
    /// What the holder of `membership` sees; `departure` is how they left, if they did. `None`
    /// for one who sees nothing more: they left, or cleared a group they were removed from.
    pub fn for_reader(membership: &Membership, departure: Option<&Departure>) -> Option<Self> {
        let until = match membership.left_at {
            None => None,
            Some(_) => Some(departure?.reads_until()?),
        };
        Some(Self {
            since: membership.joined_at,
            until,
        })
    }

    pub fn contains(&self, at: OffsetDateTime) -> bool {
        at >= self.since && self.until.is_none_or(|until| at <= until)
    }
}

/// An event with the names this instance shows its maker and its subject by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedEvent {
    pub event: GroupEvent,
    pub by_name: Option<String>,
    pub subject_name: Option<String>,
}

#[cfg(test)]
mod tests;
