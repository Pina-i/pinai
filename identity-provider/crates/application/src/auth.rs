//! Signing in over OpenID Connect: a client's request, the credentials, the code it ends in and
//! the tokens that code is exchanged for.

mod authenticate;
mod authorize;
mod exchange_code;
mod link_device;
mod log_in;
mod log_out;
mod pass_second_factor;
mod refresh;
mod register;
mod resend_code;
mod revoke_token;
mod send_test_mail;
mod show_sign_in;
mod sign_out_others;
mod sweep_signups;
mod totp_enrollment;
mod totp_settings;
mod verify_email;
#[cfg(test)]
mod world;

pub use authenticate::Authenticate;
pub use authorize::{Authorize, AuthorizeCommand, Authorized};
pub use exchange_code::{ExchangeCode, TokenCommand};
pub use link_device::LinkDevice;
pub use log_in::{LogIn, LoginOutcome};
pub use log_out::LogOut;
pub use pass_second_factor::{PassSecondFactor, SecondFactorOutcome};
pub use refresh::{Refresh, RefreshCommand};
pub use register::{Register, RegisterCommand, Registered};
pub use resend_code::ResendCode;
pub use revoke_token::RevokeToken;
pub use send_test_mail::SendTestMail;
pub use show_sign_in::ShowSignIn;
pub use sign_out_others::SignOutOthers;
pub use sweep_signups::{SweepSignups, Swept};
pub use totp_enrollment::{ConfirmTotpEnrollment, StartTotpEnrollment};
pub use totp_settings::{DisableTotp, RegenerateRecoveryCodes};
pub use verify_email::{Verification, VerifyEmail};

use std::sync::Arc;

use domain::auth::{
    AuthError, AuthorizationCode, AuthorizationCodes, AuthorizationRequest, CODE_TTL, ClientSignIn,
    ClientSignIns, Grant, RESEND_LIMIT, RESEND_WINDOW, RevokedReason, SIGNUP_CODE_TTL, Session,
    SessionKind, SessionNotifier, Sessions, SignInAccount, SignupCodes, SignupMailer,
};
use domain::{SessionId, UserId};
use time::OffsetDateTime;

/// The end every password sign-in shares — the login form, the sign-up code, the second factor:
/// the app remembered for the account, the browser's session, and the code.
pub struct CompleteSignIn {
    sign_ins: Arc<dyn ClientSignIns>,
    codes: Arc<dyn AuthorizationCodes>,
    sessions: Arc<dyn Sessions>,
    notifier: Arc<dyn SessionNotifier>,
}

impl CompleteSignIn {
    pub fn new(
        sign_ins: Arc<dyn ClientSignIns>,
        codes: Arc<dyn AuthorizationCodes>,
        sessions: Arc<dyn Sessions>,
        notifier: Arc<dyn SessionNotifier>,
    ) -> Self {
        Self {
            sign_ins,
            codes,
            sessions,
            notifier,
        }
    }

    /// `current` is the session the browser holds already: kept when it is this account's and
    /// live, ended when it is another's — a browser is signed in as one account at a time.
    pub(crate) async fn execute(
        &self,
        user: UserId,
        request: &AuthorizationRequest,
        current: Option<SessionId>,
        now: OffsetDateTime,
    ) -> Result<(SessionId, AuthorizationCode), AuthError> {
        let held = match current {
            Some(id) => self.sessions.find(id).await?,
            None => None,
        };
        let session = match held.filter(|held| held.is_live(now)) {
            Some(held) if held.user == user => {
                self.sessions.touch(held.id, now).await?;
                held.id
            }
            other => {
                if let Some(other) = other {
                    end_session(
                        &*self.sessions,
                        &*self.notifier,
                        other.id,
                        RevokedReason::Replaced,
                        now,
                    )
                    .await?;
                }
                self.sessions.open(user, &SessionKind::Browser, now).await?
            }
        };
        self.sign_ins
            .remember(&ClientSignIn::of(user, request), now)
            .await?;
        let code = self
            .codes
            .issue(&Grant::answering(user, session, request), now + CODE_TTL)
            .await?;
        Ok((session, code))
    }
}

/// Ends a session, and closes what hangs on it.
pub(crate) async fn end_session(
    sessions: &dyn Sessions,
    notifier: &dyn SessionNotifier,
    id: SessionId,
    reason: RevokedReason,
    now: OffsetDateTime,
) -> Result<(), AuthError> {
    let Some(session) = sessions.find(id).await? else {
        return Ok(());
    };
    if sessions.revoke(id, reason, now).await? {
        notifier.ended(&session);
    }
    Ok(())
}

/// Closes what hangs on each of the sessions just ended.
pub(crate) fn tell_ended(notifier: &dyn SessionNotifier, ended: &[Session]) {
    for session in ended {
        notifier.ended(session);
    }
}

/// A fresh code to confirm the account's address, by mail; its earlier codes stop working.
/// Within the resend limit, whoever asks: past it, `TooManyCodes` — each code is more mail to
/// the address, and more guesses at it.
pub(crate) async fn mail_signup_code(
    codes: &dyn SignupCodes,
    mailer: &dyn SignupMailer,
    account: &SignInAccount,
    now: OffsetDateTime,
) -> Result<(), AuthError> {
    if codes.issued_since(account.id, now - RESEND_WINDOW).await? >= RESEND_LIMIT {
        return Err(AuthError::TooManyCodes);
    }
    let code = codes.issue(account.id, now + SIGNUP_CODE_TTL).await?;
    let name = account
        .display_name
        .as_deref()
        .filter(|name| !name.is_empty())
        .unwrap_or(&account.username);
    mailer.send_code(&account.email, name, &code).await
}
