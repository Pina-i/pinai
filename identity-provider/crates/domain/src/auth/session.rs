use time::{Duration, OffsetDateTime};

use crate::{DeviceId, SessionId, UserId};

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
    /// The E2EE device it signed in, once its client said: revoking the device ends it.
    pub device: Option<DeviceId>,
    pub created_at: OffsetDateTime,
    /// The last sign-in or refresh that used it.
    pub last_used_at: OffsetDateTime,
    /// The last time the account typed its password on it: what its tokens carry as `auth_time`,
    /// and what a sensitive action asks to be recent. Neither a refresh nor a silent sign-in
    /// changes it.
    pub authenticated_at: OffsetDateTime,
    pub revoked_at: Option<OffsetDateTime>,
}

impl Session {
    pub fn is_live(&self, now: OffsetDateTime) -> bool {
        self.revoked_at.is_none() && now - self.last_used_at < SESSION_IDLE
    }
}

/// When `device` was last used signed in: its live session's last use, `None` when it is signed
/// out.
pub fn last_active(
    sessions: &[Session],
    device: DeviceId,
    now: OffsetDateTime,
) -> Option<OffsetDateTime> {
    sessions
        .iter()
        .filter(|session| session.device == Some(device) && session.is_live(now))
        .map(|session| session.last_used_at)
        .max()
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
    /// Another sign-in took its place: another account on the same browser, or a new session
    /// on the same device.
    Replaced,
    /// A refresh token of it was presented again after its rotation: two copies exist.
    Reuse,
    /// Its device was revoked.
    DeviceRevoked,
    /// Its account signed out of every other device.
    SignedOutElsewhere,
}

impl RevokedReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SignOut => "sign_out",
            Self::Replaced => "replaced",
            Self::Reuse => "reuse",
            Self::DeviceRevoked => "device_revoked",
            Self::SignedOutElsewhere => "signed_out_elsewhere",
        }
    }
}

#[cfg(test)]
mod tests;
