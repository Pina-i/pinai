use std::sync::Arc;

use domain::UserId;
use domain::auth::{AuthError, SignInAccounts, SignupCodes, SignupMailer};
use time::OffsetDateTime;

use super::mail_signup_code;

/// `POST /verify-email/resend`: another code, within the limit.
pub struct ResendCode {
    accounts: Arc<dyn SignInAccounts>,
    codes: Arc<dyn SignupCodes>,
    mailer: Arc<dyn SignupMailer>,
}

impl ResendCode {
    pub fn new(
        accounts: Arc<dyn SignInAccounts>,
        codes: Arc<dyn SignupCodes>,
        mailer: Arc<dyn SignupMailer>,
    ) -> Self {
        Self {
            accounts,
            codes,
            mailer,
        }
    }

    pub async fn execute(&self, user: UserId, now: OffsetDateTime) -> Result<(), AuthError> {
        let account = self
            .accounts
            .by_id(user)
            .await?
            .ok_or(AuthError::UnknownUser)?;
        if account.email_verified {
            return Err(AuthError::AlreadyVerified);
        }
        mail_signup_code(&*self.codes, &*self.mailer, &account, now).await
    }
}

#[cfg(test)]
mod tests;
