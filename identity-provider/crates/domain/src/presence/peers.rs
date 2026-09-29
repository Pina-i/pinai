use std::collections::{HashMap, HashSet};

use crate::ConversationId;
use crate::identity::{ActorUri, Domain, InstanceOrigin};
use crate::messaging::Member;

use super::Signal;

/// A conversation's members on other instances, by instance: each needs one stream from its
/// instance while the conversation is open here.
pub fn remote_members_by_domain(
    members: &[Member],
    origin: &InstanceOrigin,
) -> HashMap<Domain, Vec<ActorUri>> {
    let mut by_domain: HashMap<Domain, Vec<ActorUri>> = HashMap::new();
    for member in members.iter().filter(|m| !origin.owns(&m.actor_uri)) {
        by_domain
            .entry(member.actor_uri.domain().clone())
            .or_default()
            .push(member.actor_uri.clone());
    }
    by_domain
}

/// Whether `peer` may tell of the signal's actor: each instance speaks for its own accounts.
pub fn speaks_for(peer: &Domain, signal: &Signal) -> bool {
    signal.actor().domain() == peer
}

/// What a peer's stream carries: the presence of the actors it may follow, and their typing in
/// the conversations it may follow.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeerFilter {
    pub actors: HashSet<ActorUri>,
    pub conversations: HashSet<ConversationId>,
}

impl PeerFilter {
    pub fn admits(&self, signal: &Signal) -> bool {
        match signal {
            Signal::Presence(event) => self.actors.contains(&event.actor),
            Signal::Typing(event) => {
                self.actors.contains(&event.actor)
                    && self.conversations.contains(&event.conversation)
            }
        }
    }
}

#[cfg(test)]
mod tests;
