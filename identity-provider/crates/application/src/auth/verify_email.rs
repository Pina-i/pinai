use std::sync::Arc;

use domain::UserId;
use domain::auth::{
    AuthError, AuthorizationCode, AuthorizationCodes, AuthorizationRequest, ClientSignIns, Clients,
    CodeAttempt, OtpCode, SignInAccounts, SignupCodes,
};
use time::OffsetDateTime;

use super::signed_in;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verification {
    /// The address is confirmed: back to the client with a code.
    SignedIn {
        user: UserId,
        code: AuthorizationCode,
    },
    /// Confirmed before: nothing to spend, signing in will do.
    AlreadyConfirmed,
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
    authorization_codes: Arc<dyn AuthorizationCodes>,
    sign_ins: Arc<dyn ClientSignIns>,
}

impl VerifyEmail {
    pub fn new(
        clients: Arc<dyn Clients>,
        accounts: Arc<dyn SignInAccounts>,
        codes: Arc<dyn SignupCodes>,
        authorization_codes: Arc<dyn AuthorizationCodes>,
        sign_ins: Arc<dyn ClientSignIns>,
    ) -> Self {
        Self {
            clients,
            accounts,
            codes,
            authorization_codes,
            sign_ins,
        }
    }

    pub async fn execute(
        &self,
        user: UserId,
        code: &str,
        request: &AuthorizationRequest,
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
        if account.email_verified {
            return Ok(Verification::AlreadyConfirmed);
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
                let code = signed_in(
                    &*self.sign_ins,
                    &*self.authorization_codes,
                    user,
                    request,
                    now,
                )
                .await?;
                Ok(Verification::SignedIn { user, code })
            }
            refused => Ok(Verification::Refused(refused)),
        }
    }
}

#[cfg(test)]
mod tests;
