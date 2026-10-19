use time::{Duration, OffsetDateTime};

use crate::SessionId;

use super::ClientId;

pub const REFRESH_GRANT_TYPE: &str = "refresh_token";

/// How long a rotated refresh token may come again, for an answer lost on its way back. Past it,
/// a second presentation means a second copy.
pub const REFRESH_GRACE: Duration = Duration::seconds(60);

/// A refresh token as its client holds it. Only a hash of it is kept.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RefreshToken(String);

impl RefreshToken {
    pub fn new(token: String) -> Self {
        Self(token)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A kept refresh token, as a presentation of it finds it. Each use rotates a token to a
/// successor, so a session's chain has one token unrotated: its head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshLink {
    pub session: SessionId,
    pub client: ClientId,
    /// When it was used; `None` for the head of its chain.
    pub rotated_at: Option<OffsetDateTime>,
    /// Its successor is the head still, never used.
    pub successor_unused: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presentation {
    /// Another client's: refused, nothing changes.
    Refused,
    /// The head: rotated to a new head.
    Rotate,
    /// Rotated moments ago and its successor never used, so the answer was lost: a new successor
    /// replaces the one that never arrived.
    Retry,
    /// Rotated, and here again: two copies exist, and its session ends.
    Reuse,
}

impl RefreshLink {
    pub fn presented(&self, client: &ClientId, now: OffsetDateTime) -> Presentation {
        if self.client != *client {
            return Presentation::Refused;
        }
        match self.rotated_at {
            None => Presentation::Rotate,
            Some(at) if self.successor_unused && now - at <= REFRESH_GRACE => Presentation::Retry,
            Some(_) => Presentation::Reuse,
        }
    }
}

/// What presenting a refresh token came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rotation {
    /// Unknown, or another client's: nothing changed.
    Refused,
    Rotated {
        session: SessionId,
        successor: RefreshToken,
    },
    /// Presented again after its rotation: its session must end.
    Reused { session: SessionId },
}

#[cfg(test)]
mod tests;
