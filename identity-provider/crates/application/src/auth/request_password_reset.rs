use std::sync::Arc;

use domain::auth::{
    AuthError, Email, PasswordResets, REQUESTED_RESET_TTL, Registrations, ResetMail, ResetMailer,
    SignInAccounts, reset_link, reset_requester,
};
use domain::identity::InstanceOrigin;
use time::OffsetDateTime;

/// `POST /forgot-password` on an open instance: a single-use link, open for
/// [`REQUESTED_RESET_TTL`], mailed to the account with the address, replacing the link it had
/// open. The asker is told the same whatever the address, so the outcome here is the same too:
/// no account, one still to confirm its address, or one past the limit mail nothing.
pub struct RequestPasswordReset {
    registrations: Registrations,
    origin: InstanceOrigin,
    /// The instance's name, as its pages show it.
    instance: String,
    accounts: Arc<dyn SignInAccounts>,
    resets: Arc<dyn PasswordResets>,
    mailer: Arc<dyn ResetMailer>,
}

impl RequestPasswordReset {
    pub fn new(
        registrations: Registrations,
        origin: InstanceOrigin,
        instance: String,
        accounts: Arc<dyn SignInAccounts>,
        resets: Arc<dyn PasswordResets>,
        mailer: Arc<dyn ResetMailer>,
    ) -> Self {
        Self {
            registrations,
            origin,
            instance,
            accounts,
            resets,
            mailer,
        }
    }

    /// The address asked about, before the request is answered: `NoResetByMail` on an
    /// invite-only instance, `BadEmail` for what is no address. Nothing here asks whose it is.
    pub fn accept(&self, address: &str) -> Result<Email, AuthError> {
        self.registrations.allow_reset_by_mail()?;
        Email::parse(address).map_err(AuthError::BadEmail)
    }

    /// Once the request is answered: the link, mailed, when the address has an account that may
    /// get one.
    pub async fn execute(&self, address: &Email, now: OffsetDateTime) -> Result<(), AuthError> {
        self.registrations.allow_reset_by_mail()?;
        let Some(account) = reset_requester(self.accounts.by_email(address).await?) else {
            return Ok(());
        };
        let Some(token) = self
            .resets
            .request(account.id, now, now + REQUESTED_RESET_TTL)
            .await?
        else {
            tracing::info!(user = %account.id, "reset links asked for past the limit: none mailed");
            return Ok(());
        };
        let mail = ResetMail {
            to: account.email.clone(),
            name: account.addressed_as().to_owned(),
            instance: self.instance.clone(),
            link: reset_link(&self.origin, &token),
            valid_for: REQUESTED_RESET_TTL,
        };
        if let Err(failed) = self.mailer.send_reset_link(&mail).await {
            if let Err(e) = self.resets.withdraw(&token, now).await {
                tracing::warn!(user = %account.id, error = ?e, "a reset link whose mail failed not withdrawn");
            }
            return Err(failed);
        }
        tracing::info!(user = %account.id, "mailed a reset link asked for");
        Ok(())
    }
}

#[cfg(test)]
mod tests;
