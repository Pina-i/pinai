use time::{Duration, OffsetDateTime};

use crate::{SessionId, UserId};

use super::ClientId;

/// A session ends after this long without use, however long it lasted before: an active user
/// never signs in again.
pub const SESSION_IDLE: Duration = Duration::days(90);
/// An ended session is kept this long, then swept.
pub const SESSION_RETENTION: Duration = Duration::days(30);

/// A signed-in account, as this instance keeps it: what every access token and refresh token
/// belongs to, so ending it signs them all out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub id: SessionId,
    pub user: UserId,
    pub kind: SessionKind,
    pub created_at: OffsetDateTime,
    /// The last sign-in or refresh that used it.
    pub last_used_at: OffsetDateTime,
    pub revoked_at: Option<OffsetDateTime>,
}

impl Session {
    pub fn is_live(&self, now: OffsetDateTime) -> bool {
        self.revoked_at.is_none() && now - self.last_used_at < SESSION_IDLE
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionKind {
    /// A browser signed in with a password: what the `idp_session` cookie names, and what lets
    /// `/authorize` skip the login page.
    Browser,
    /// A native client's own, opened by its code exchange with `offline_access`: it stays on the
    /// device, apart from the browser the user signed in through.
    App(ClientId),
}

/// Why a session ended before its time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevokedReason {
    /// `/logout`.
    SignOut,
    /// Another account signed in on the same browser.
    Replaced,
    /// A refresh token of it was presented again after its rotation: two copies exist.
    Reuse,
}

impl RevokedReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SignOut => "sign_out",
            Self::Replaced => "replaced",
            Self::Reuse => "reuse",
        }
    }
}

#[cfg(test)]
mod tests;
