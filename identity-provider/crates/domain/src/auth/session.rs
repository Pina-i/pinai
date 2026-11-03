use time::{Duration, OffsetDateTime};

use crate::{DeviceId, SessionId, UserId};

use super::{AuthError, ClientId};

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
    /// The last sign-in or refresh that used it. A web app's is never later than its browser
    /// session's: each use of it is one of the browser session too, and no use sets one back.
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

    /// The browser session it hangs under: a web app's.
    pub fn browser(&self) -> Option<SessionId> {
        match self.kind {
            SessionKind::Web { browser, .. } => Some(browser),
            SessionKind::Browser | SessionKind::App(_) => None,
        }
    }

    /// A code issued under it opens or reuses a web app's session `now`: a browser session, live.
    pub fn signs_apps_in(&self, now: OffsetDateTime) -> bool {
        self.kind == SessionKind::Browser && self.is_live(now)
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

/// What ending `ended` ends among an account's `sessions`: it, and every session under it — a
/// browser session's web apps go with it.
pub fn ending(sessions: &[Session], ended: SessionId) -> Vec<SessionId> {
    unrevoked(sessions)
        .filter(|session| session.id == ended || session.browser() == Some(ended))
        .map(|session| session.id)
        .collect()
}

/// What revoking `device` ends among an account's `sessions`: the sessions naming it and, above a
/// web app's, the browser session with every session under it — that browser's cookie would
/// otherwise sign the device in again, silently, as a new one.
pub fn ending_with_device(sessions: &[Session], device: DeviceId) -> Vec<SessionId> {
    let browsers: Vec<SessionId> = unrevoked(sessions)
        .filter(|session| session.device == Some(device))
        .filter_map(Session::browser)
        .collect();
    unrevoked(sessions)
        .filter(|session| {
            session.device == Some(device)
                || browsers.contains(&session.id)
                || session
                    .browser()
                    .is_some_and(|browser| browsers.contains(&browser))
        })
        .map(|session| session.id)
        .collect()
}

/// What signing out of every other device ends among an account's `sessions`: all but `keep`'s
/// browser — the browser session it hangs under and every web app's there, which would sign in
/// again through its cookie anyway. A desktop app keeps its own session only.
pub fn ending_all_but(sessions: &[Session], keep: SessionId) -> Vec<SessionId> {
    let kept_browser = sessions
        .iter()
        .find(|session| session.id == keep)
        .and_then(Session::browser);
    unrevoked(sessions)
        .filter(|session| {
            session.id != keep
                && kept_browser.is_none_or(|browser| {
                    session.id != browser && session.browser() != Some(browser)
                })
        })
        .map(|session| session.id)
        .collect()
}

/// Whether `session` may name `device` now: live, a web app's or an app's — a browser session
/// names none, its web apps' sessions name theirs —, and naming none yet or that very one.
pub fn may_link(session: &Session, device: DeviceId, now: OffsetDateTime) -> Result<(), AuthError> {
    if !session.is_live(now) {
        return Err(AuthError::SessionEnded);
    }
    match (&session.kind, session.device) {
        (SessionKind::Browser, _) => Err(AuthError::DeviceMismatch),
        (_, Some(named)) if named != device => Err(AuthError::DeviceMismatch),
        _ => Ok(()),
    }
}

/// What a client's code exchange under a browser session does with the session it holds there,
/// not revoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebAppSignIn {
    /// Live: used again, so the device it names stays named.
    Reuse(SessionId),
    /// Idle past its time: it ends (`replaced`), and a new one opens.
    Replace(SessionId),
    /// None held: a new one opens.
    Open,
}

pub fn web_app_sign_in(held: Option<&Session>, now: OffsetDateTime) -> WebAppSignIn {
    match held {
        Some(held) if held.is_live(now) => WebAppSignIn::Reuse(held.id),
        Some(held) => WebAppSignIn::Replace(held.id),
        None => WebAppSignIn::Open,
    }
}

fn unrevoked(sessions: &[Session]) -> impl Iterator<Item = &Session> {
    sessions
        .iter()
        .filter(|session| session.revoked_at.is_none())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionKind {
    /// A browser signed in with a password: what the `idp_session` cookie names, and what lets
    /// `/authorize` skip the login page. Its codes' tokens belong to the apps' sessions under it,
    /// never to it, so it names no device.
    Browser,
    /// A client's own under the browser session its code was issued under — a web app's, or any
    /// client's that doesn't stay signed in: one live per browser session and client, reused by
    /// its next sign-in there so its device stays named, and ended with that browser session.
    Web {
        client: ClientId,
        browser: SessionId,
    },
    /// A native client's own, opened by its code exchange with `offline_access`: it stays on the
    /// device, apart from the browser the user signed in through.
    App(ClientId),
}

/// Why a session ended before its time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevokedReason {
    /// `/logout`, or `/revoke`.
    SignOut,
    /// Another sign-in took its place: another account on the same browser, a new session on
    /// the same device, or a web app's new session where an idle one stood.
    Replaced,
    /// A refresh token of it was presented again after its rotation: two copies exist.
    Reuse,
    /// Its device was revoked, or a device of a web app signed in through the same browser
    /// session.
    DeviceRevoked,
    /// Its account signed out of every other device.
    SignedOutElsewhere,
    /// Its account's password was set anew with a reset link.
    PasswordReset,
}

impl RevokedReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SignOut => "sign_out",
            Self::Replaced => "replaced",
            Self::Reuse => "reuse",
            Self::DeviceRevoked => "device_revoked",
            Self::SignedOutElsewhere => "signed_out_elsewhere",
            Self::PasswordReset => "password_reset",
        }
    }
}

#[cfg(test)]
mod tests;
