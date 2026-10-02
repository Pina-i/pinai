use time::OffsetDateTime;

use super::conversation::{Conversation, GroupChanges, Member, Membership, Role, StampedName};
use super::group::{GroupName, MAX_MEMBERS};
use crate::ConversationId;
use crate::identity::ActorUri;

/// A change to a group, as the instance where it was made tells the others holding its members —
/// identity-provider/specs/03-direct-messages.md § 10, Group changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupChange {
    pub group: ConversationId,
    /// An admin of the group; for a leave, the member leaving.
    pub by: ActorUri,
    /// When it was made, where it was: its stamp.
    pub at: OffsetDateTime,
    pub kind: GroupChangeKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupChangeKind {
    /// Joins, or joins again, as a member.
    Added(ActorUri),
    Removed(ActorUri),
    Left,
    Renamed(GroupName),
    RoleChanged(ActorUri, Role),
}

/// What a copy of the group does with a change it takes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupEffect {
    /// Hold a member, or a name, as given.
    Take(GroupChanges),
    /// The member is out since `at`; `removed_by` is `None` for a leave.
    Depart {
        member: ActorUri,
        at: OffsetDateTime,
        removed_by: Option<ActorUri>,
    },
}

impl GroupChange {
    /// The member it is about: the one added, removed or given a role, or the one leaving.
    pub fn subject(&self) -> Option<&ActorUri> {
        match &self.kind {
            GroupChangeKind::Added(member)
            | GroupChangeKind::Removed(member)
            | GroupChangeKind::RoleChanged(member, _) => Some(member),
            GroupChangeKind::Left => Some(&self.by),
            GroupChangeKind::Renamed(_) => None,
        }
    }

    /// Whether its maker may make it, as this copy holds the group's `members`: an admin, or for a
    /// leave the member leaving.
    pub fn is_entitled(&self, members: &[Member]) -> bool {
        let maker = members.iter().find(|m| m.actor_uri == self.by);
        match self.kind {
            GroupChangeKind::Left => maker.is_some(),
            _ => maker.is_some_and(|m| m.role == Role::Admin),
        }
    }

    /// Whether it may come in through `owner`'s inbox: a peer only ever acts on a group through
    /// one of its members here — or the one it adds.
    pub fn may_arrive_through(&self, owner: &ActorUri, members: &[Member]) -> bool {
        members.iter().any(|m| &m.actor_uri == owner)
            || matches!(&self.kind, GroupChangeKind::Added(added) if added == owner)
    }

    /// What a copy holding `group` and `held` takes from it: as for a roster, the newer stamp
    /// wins, so a change arriving late, or twice, undoes nothing.
    pub fn effect(&self, group: &Conversation, held: &[Membership]) -> Option<GroupEffect> {
        let of = |actor: &ActorUri| held.iter().find(|m| &m.member.actor_uri == actor);
        let take = |membership: Membership| {
            GroupEffect::Take(GroupChanges {
                name: None,
                members: vec![membership],
            })
        };
        match &self.kind {
            GroupChangeKind::Added(member) => match of(member) {
                Some(active) if active.is_active() => (self.at > active.joined_at).then(|| {
                    take(Membership {
                        joined_at: self.at,
                        ..active.clone()
                    })
                }),
                departed => {
                    let comes_back =
                        departed.is_none_or(|d| d.left_at.is_some_and(|l| self.at > l));
                    let room = held.iter().filter(|m| m.is_active()).count() < MAX_MEMBERS;
                    (comes_back && room).then(|| {
                        take(Membership {
                            member: Member {
                                actor_uri: member.clone(),
                                role: Role::Member,
                            },
                            joined_at: self.at,
                            role_at: self.at,
                            left_at: None,
                        })
                    })
                }
            },
            GroupChangeKind::Removed(member) => self.departure(of(member), member, true),
            GroupChangeKind::Left => self.departure(of(&self.by), &self.by, false),
            GroupChangeKind::Renamed(name) => (self.at > group.name_at).then(|| {
                GroupEffect::Take(GroupChanges {
                    name: Some(StampedName {
                        name: Some(name.as_str().to_owned()),
                        at: self.at,
                    }),
                    members: Vec::new(),
                })
            }),
            GroupChangeKind::RoleChanged(member, role) => {
                let held = of(member).filter(|m| m.is_active() && self.at > m.role_at)?;
                Some(take(Membership {
                    member: Member {
                        actor_uri: member.clone(),
                        role: *role,
                    },
                    role_at: self.at,
                    ..held.clone()
                }))
            }
        }
    }

    fn departure(
        &self,
        held: Option<&Membership>,
        member: &ActorUri,
        removed: bool,
    ) -> Option<GroupEffect> {
        held.filter(|m| m.is_active() && self.at > m.joined_at)?;
        Some(GroupEffect::Depart {
            member: member.clone(),
            at: self.at,
            removed_by: removed.then(|| self.by.clone()),
        })
    }
}

#[cfg(test)]
mod tests;
