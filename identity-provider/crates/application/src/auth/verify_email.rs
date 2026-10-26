use std::sync::Arc;

use domain::auth::{
    AuthError, AuthorizationCode, AuthorizationRequest, Clients, CodeAttempt, OtpCode,
    SignInAccounts, SignupCodes,
};
use domain::{SessionId, UserId};
use time::OffsetDateTime;

use super::CompleteSignIn;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verification {
    /// The address is confirmed: back to the client with a code.
    SignedIn {
        user: UserId,
        session: SessionId,
        code: AuthorizationCode,
    },
    /// Confirmed before: nothing to spend, signing in will do.
    AlreadyConfirmed,
    /// Admitted: it signs in with its password alone, never with a code — its address was never
    /// proven, so a code must not stand in for the password.
    NoCodeNeeded,
    /// Not six digits: not tried.
    Malformed,
    /// Tried and refused.
    Refused(CodeAttempt),
}

/// `POST /verify-email-and-login`: the code mailed at registration, and the sign-in it
/// continues.
pub struct VerifyEmail {
    clients: Arc<dyn Clients>,
    accounts: Arc<dyn SignInAccounts>,
    codes: Arc<dyn SignupCodes>,
    complete: Arc<CompleteSignIn>,
}

impl VerifyEmail {
    pub fn new(
        clients: Arc<dyn Clients>,
        accounts: Arc<dyn SignInAccounts>,
        codes: Arc<dyn SignupCodes>,
        complete: Arc<CompleteSignIn>,
    ) -> Self {
        Self {
            clients,
            accounts,
            codes,
            complete,
        }
    }

    pub async fn execute(
        &self,
        user: UserId,
        code: &str,
        request: &AuthorizationRequest,
        current: Option<SessionId>,
        now: OffsetDateTime,
    ) -> Result<Verification, AuthError> {
        let Ok(code) = OtpCode::parse(code) else {
            return Ok(Verification::Malformed);
        };
        let account = self
            .accounts
            .by_id(user)
            .await?
            .ok_or(AuthError::UnknownUser)?;
        if !account.needs_code() {
            return Ok(if account.email_verified {
                Verification::AlreadyConfirmed
            } else {
                Verification::NoCodeNeeded
            });
        }
        // The request is checked before the code is tried: a code is spent only on a sign-in
        // that can go through.
        let client = self
            .clients
            .find(&request.client)
            .await?
            .ok_or(AuthError::UnknownClient)?;
        if !client.allows(&request.redirect_uri) {
            return Err(AuthError::UnregisteredRedirect);
        }
        match self.codes.attempt(user, &code, now).await? {
            CodeAttempt::Confirmed => {
                let (session, code) = self.complete.execute(user, request, current, now).await?;
                Ok(Verification::SignedIn {
                    user,
                    session,
                    code,
                })
            }
            refused => Ok(Verification::Refused(refused)),
        }
    }
}

#[cfg(test)]
mod tests;
