use std::sync::Arc;

use domain::auth::{
    AuthError, AuthorizationCode, AuthorizationRequest, Clients, Email, LOGIN_TICKET_TTL,
    LoginTickets, PasswordHasher, SignInAccounts, SignupCodes, SignupMailer,
};
use domain::{SessionId, TicketId, UserId};
use time::OffsetDateTime;

use super::{CompleteSignIn, mail_signup_code};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginOutcome {
    /// Wrong email or password — which one is never said.
    Refused,
    /// The right password, but the address is unconfirmed and was never admitted: a code was
    /// mailed to it.
    Unverified { user: UserId, email: String },
    /// The right password; the authenticator's code comes next, against this ticket.
    SecondFactor(TicketId),
    SignedIn {
        user: UserId,
        /// The browser session to set the cookie for.
        session: SessionId,
        code: AuthorizationCode,
    },
}

/// `POST /login`: an email and a password, answering a client's request.
pub struct LogIn {
    clients: Arc<dyn Clients>,
    accounts: Arc<dyn SignInAccounts>,
    hasher: Arc<dyn PasswordHasher>,
    tickets: Arc<dyn LoginTickets>,
    signup_codes: Arc<dyn SignupCodes>,
    mailer: Arc<dyn SignupMailer>,
    complete: Arc<CompleteSignIn>,
}

impl LogIn {
    pub fn new(
        clients: Arc<dyn Clients>,
        accounts: Arc<dyn SignInAccounts>,
        hasher: Arc<dyn PasswordHasher>,
        tickets: Arc<dyn LoginTickets>,
        signup_codes: Arc<dyn SignupCodes>,
        mailer: Arc<dyn SignupMailer>,
        complete: Arc<CompleteSignIn>,
    ) -> Self {
        Self {
            clients,
            accounts,
            hasher,
            tickets,
            signup_codes,
            mailer,
            complete,
        }
    }

    pub async fn execute(
        &self,
        email: &str,
        password: &str,
        request: &AuthorizationRequest,
        current: Option<SessionId>,
        now: OffsetDateTime,
    ) -> Result<LoginOutcome, AuthError> {
        // The form is posted by a browser, not by `/authorize`: its request is checked again, or
        // any page could have a code sent wherever it names.
        let client = self
            .clients
            .find(&request.client)
            .await?
            .ok_or(AuthError::UnknownClient)?;
        if !client.allows(&request.redirect_uri) {
            return Err(AuthError::UnregisteredRedirect);
        }
        let account = match Email::parse(email) {
            Ok(email) => self.accounts.by_email(&email).await?,
            Err(_) => None,
        };
        // An unknown email is checked against a decoy: answering sooner would tell who has an
        // account here.
        let hash = account
            .as_ref()
            .map_or(self.hasher.decoy(), |account| &account.password_hash);
        let matched = self.hasher.verify(password, hash);
        let Some(account) = account.filter(|_| matched) else {
            return Ok(LoginOutcome::Refused);
        };
        if account.needs_code() {
            match mail_signup_code(&*self.signup_codes, &*self.mailer, &account, now).await {
                // The codes already mailed still work.
                Ok(()) | Err(AuthError::TooManyCodes) => {}
                Err(e) => {
                    tracing::warn!(user = %account.id, error = ?e, "signup code not mailed on sign-in")
                }
            }
            return Ok(LoginOutcome::Unverified {
                user: account.id,
                email: account.email,
            });
        }
        if account.totp_enabled {
            let ticket = self
                .tickets
                .open(account.id, request, now + LOGIN_TICKET_TTL)
                .await?;
            return Ok(LoginOutcome::SecondFactor(ticket));
        }
        let (session, code) = self
            .complete
            .execute(account.id, request, current, now)
            .await?;
        Ok(LoginOutcome::SignedIn {
            user: account.id,
            session,
            code,
        })
    }
}

#[cfg(test)]
mod tests;
