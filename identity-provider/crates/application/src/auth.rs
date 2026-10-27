//! Signing in over OpenID Connect: a client's request, the credentials, the code it ends in and
//! the tokens that code is exchanged for.

mod authenticate;
mod authorize;
mod ensure_admin;
mod exchange_code;
mod invitations;
mod link_device;
mod list_members;
mod log_in;
mod log_out;
mod pass_second_factor;
mod password_resets;
mod refresh;
mod register;
mod register_invited;
mod request_password_reset;
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
pub use ensure_admin::EnsureAdmin;
pub use exchange_code::{ExchangeCode, TokenCommand};
pub use invitations::{CreateInvitation, CreatedInvitation, ListInvitations, RevokeInvitation};
pub use link_device::LinkDevice;
pub use list_members::{ListMembers, ListedMember};
pub use log_in::{LogIn, LoginOutcome};
pub use log_out::LogOut;
pub use pass_second_factor::{PassSecondFactor, SecondFactorOutcome};
pub use password_resets::{IssuePasswordReset, IssuedReset, ResetPassword};
pub use refresh::{Refresh, RefreshCommand};
pub use register::{Register, RegisterCommand, Registered};
pub use register_invited::{Joined, RegisterInvited};
pub use request_password_reset::RequestPasswordReset;
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
    ClientSignIns, Email, Grant, HandleSuffixes, NewAccount, PasswordHash, RESEND_LIMIT,
    RESEND_WINDOW, Registration, RevokedReason, SIGNUP_CODE_TTL, Session, SessionKind,
    SessionNotifier, Sessions, SignInAccount, SignInAccounts, SignUps, SignupCodes, SignupMailer,
};
use domain::identity::{Handle, InstanceOrigin, UsernameChoice};
use domain::profile::DisplayName;
use domain::{InvitationId, SessionId, UserId};
use time::OffsetDateTime;

/// Suffixes drawn for one chosen name before giving up: 36⁵ of them make a second a rarity.
const SUFFIX_DRAWS: usize = 3;

/// The end every password sign-in shares — the login form, the sign-up code, the second factor:
/// the app remembered for the account, the browser's session, and the code. Joining by invitation
/// shares it too, but the code: `signed_in`.
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
        let session = self
            .signed_in(user, &ClientSignIn::of(user, request), current, now)
            .await?;
        let code = self
            .codes
            .issue(&Grant::answering(user, session, request), now + CODE_TTL)
            .await?;
        Ok((session, code))
    }

    /// All a password sign-in leaves but the code: the browser's session, its password typed
    /// `now`, and the app it signed in to remembered — that app's consent. `current` as for
    /// [`Self::execute`].
    pub(crate) async fn signed_in(
        &self,
        user: UserId,
        app: &ClientSignIn,
        current: Option<SessionId>,
        now: OffsetDateTime,
    ) -> Result<SessionId, AuthError> {
        let held = match current {
            Some(id) => self.sessions.find(id).await?,
            None => None,
        };
        let session = match held.filter(|held| held.is_live(now)) {
            Some(held) if held.user == user => {
                self.sessions.touch(held.id, now).await?;
                self.sessions.authenticate(held.id, now).await?;
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
        self.sign_ins.remember(app, now).await?;
        Ok(session)
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
    mailer
        .send_code(&account.email, account.addressed_as(), &code)
        .await
}

/// What a new account is created as.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Creation {
    /// Registering: its address yet to confirm.
    SignUp,
    /// The instance's admin, admitted then.
    Admin(OffsetDateTime),
    /// Let in by an invitation, which it spends, and admitted then.
    Invited {
        invitation: InvitationId,
        at: OffsetDateTime,
    },
}

/// The account named `name`, its handle drawn from the name. The store has the last word on
/// both: an address registered in between is refused, and a handle taken by chance is drawn
/// again.
pub(crate) async fn create_account(
    sign_ups: &dyn SignUps,
    origin: &InstanceOrigin,
    suffixes: &dyn HandleSuffixes,
    creation: Creation,
    name: &DisplayName,
    email: &Email,
    password_hash: &PasswordHash,
) -> Result<NewAccount, AuthError> {
    let choice = UsernameChoice::derived_from(name.as_str());
    for _ in 0..SUFFIX_DRAWS {
        let handle = Handle::compose(&choice, &suffixes.fresh());
        let account = NewAccount {
            id: UserId::generate(),
            actor_uri: origin.actor_uri(&handle),
            username: handle,
            display_name: name.as_str().to_owned(),
            email: email.clone(),
            password_hash: password_hash.clone(),
        };
        let registration = match creation {
            Creation::SignUp => sign_ups.create(&account).await?,
            Creation::Admin(admitted_at) => sign_ups.create_admin(&account, admitted_at).await?,
            Creation::Invited { invitation, at } => {
                sign_ups.create_invited(&account, invitation, at).await?
            }
        };
        match registration {
            Registration::Created => return Ok(account),
            Registration::EmailTaken => return Err(AuthError::EmailTaken),
            Registration::InvitationSpent => return Err(AuthError::InvitationUnusable),
            Registration::HandleTaken => continue,
        }
    }
    Err(anyhow::anyhow!(
        "no free handle for {} in {SUFFIX_DRAWS} draws",
        choice.as_str()
    )
    .into())
}

/// Only an admin of the instance gets past: anyone else is `NotAdmin`.
pub(crate) async fn require_admin(
    accounts: &dyn SignInAccounts,
    caller: UserId,
) -> Result<(), AuthError> {
    match accounts.by_id(caller).await? {
        Some(account) if account.admin => Ok(()),
        _ => Err(AuthError::NotAdmin),
    }
}
