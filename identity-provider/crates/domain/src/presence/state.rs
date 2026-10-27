use std::fmt;
use std::str::FromStr;

use time::OffsetDateTime;

use crate::identity::ActorUri;
use crate::{ConversationId, ValidationError};

/// `online`, `away` and `offline` follow the connections and their heartbeats; `dnd` only a
/// user's choice — as are `away` (Idle) and `offline` (Invisible) when picked by hand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PresenceState {
    Online,
    Away,
    Offline,
    Dnd,
}

impl PresenceState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Online => "online",
            Self::Away => "away",
            Self::Offline => "offline",
            Self::Dnd => "dnd",
        }
    }

    /// A heartbeat brings an idle user back; a state picked by hand survives it — but for
    /// `away`, which reads the same either way.
    pub fn after_heartbeat(self) -> Option<Self> {
        (self == Self::Away).then_some(Self::Online)
    }

    /// Ten minutes without a heartbeat: only `online` becomes `away`.
    pub fn after_idle(self) -> Option<Self> {
        (self == Self::Online).then_some(Self::Away)
    }

    /// Shown as around — online, idle or busy — rather than offline. An account that picked
    /// Invisible reads `offline` to everyone, its admins included.
    pub fn is_around(self) -> bool {
        self != Self::Offline
    }
}

impl fmt::Display for PresenceState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for PresenceState {
    type Err = ValidationError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        match raw {
            "online" => Ok(Self::Online),
            "away" => Ok(Self::Away),
            "offline" => Ok(Self::Offline),
            "dnd" => Ok(Self::Dnd),
            _ => Err(ValidationError::new(
                "presence state",
                "online, away, offline or dnd",
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresenceEvent {
    pub actor: ActorUri,
    pub state: PresenceState,
    pub at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypingEvent {
    pub actor: ActorUri,
    pub conversation: ConversationId,
    pub at: OffsetDateTime,
}

/// What travels on the instance's presence bus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signal {
    Presence(PresenceEvent),
    Typing(TypingEvent),
}

impl Signal {
    /// Whose presence, or who is typing.
    pub fn actor(&self) -> &ActorUri {
        match self {
            Self::Presence(event) => &event.actor,
            Self::Typing(event) => &event.actor,
        }
    }
}

/// Only an active member of a conversation types in it.
pub fn may_type(members: &[crate::messaging::Member], actor: &ActorUri) -> bool {
    members.iter().any(|m| &m.actor_uri == actor)
}

#[cfg(test)]
mod tests;
