use crate::ValidationError;
use crate::identity::ActorUri;

use super::{Member, MessagingError, Role};

/// A group's name as a user gave it: trimmed, 1 to 100 characters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupName(String);

impl GroupName {
    pub const MAX_CHARS: usize = 100;

    pub fn parse(raw: &str) -> Result<Self, ValidationError> {
        let name = raw.trim();
        if name.is_empty() {
            return Err(ValidationError::new("name", "cannot be empty"));
        }
        if name.chars().count() > Self::MAX_CHARS {
            return Err(ValidationError::new(
                "name",
                format!("is longer than {} characters", Self::MAX_CHARS),
            ));
        }
        Ok(Self(name.to_owned()))
    }

    /// A name given at creation: blank means none, and clients title the group by its members.
    pub fn parse_optional(raw: Option<&str>) -> Result<Option<Self>, ValidationError> {
        match raw.map(str::trim) {
            None | Some("") => Ok(None),
            Some(name) => Self::parse(name).map(Some),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// How many members a group holds at most, its creator included. It also bounds what a roster
/// another instance sends can make this one look up.
pub const MAX_MEMBERS: usize = 50;

/// The roster a new group starts with: its creator as admin, then each invited actor once, as a
/// member — `MAX_MEMBERS` at most.
pub fn initial_roster(
    creator: &ActorUri,
    invited: &[ActorUri],
) -> Result<Vec<Member>, MessagingError> {
    let mut roster = vec![Member {
        actor_uri: creator.clone(),
        role: Role::Admin,
    }];
    for actor in invited {
        if !roster.iter().any(|m| &m.actor_uri == actor) {
            roster.push(Member {
                actor_uri: actor.clone(),
                role: Role::Member,
            });
        }
    }
    if roster.len() > MAX_MEMBERS {
        return Err(MessagingError::TooManyMembers(MAX_MEMBERS));
    }
    Ok(roster)
}

/// Whether a group with these active members can take one more.
pub fn has_room(members: &[Member]) -> bool {
    members.len() < MAX_MEMBERS
}

/// Only an admin manages a group. Someone outside it is told it does not exist.
pub fn authorize_admin(members: &[Member], caller: &ActorUri) -> Result<(), MessagingError> {
    match members.iter().find(|m| &m.actor_uri == caller) {
        Some(m) if m.role == Role::Admin => Ok(()),
        Some(_) => Err(MessagingError::NotAnAdmin),
        None => Err(MessagingError::ConversationNotFound),
    }
}

/// Whether `actor` may stop being an admin — by leaving, or by being made a member: only if the
/// group keeps another admin, or has nobody else left to manage.
pub fn may_stop_being_admin(members: &[Member], actor: &ActorUri) -> bool {
    let is_admin = |m: &Member| m.role == Role::Admin;
    let steps_down = members.iter().any(|m| &m.actor_uri == actor && is_admin(m));
    let others = members.iter().filter(|m| &m.actor_uri != actor);
    !steps_down || others.clone().next().is_none() || others.clone().any(is_admin)
}

#[cfg(test)]
mod tests;
