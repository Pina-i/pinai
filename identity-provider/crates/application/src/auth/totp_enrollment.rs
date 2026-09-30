use std::sync::Arc;

use domain::UserId;
use domain::auth::{AuthError, Authenticator, Enrollment, SecondFactors, SignInAccounts};
use domain::identity::InstanceOrigin;
use time::OffsetDateTime;

/// `POST /api/totp/enroll`: a fresh secret for the account's authenticator app, kept aside until
/// a first code confirms it.
pub struct StartTotpEnrollment {
    origin: InstanceOrigin,
    accounts: Arc<dyn SignInAccounts>,
    factors: Arc<dyn SecondFactors>,
    authenticator: Arc<dyn Authenticator>,
}

impl StartTotpEnrollment {
    pub fn new(
        origin: InstanceOrigin,
        accounts: Arc<dyn SignInAccounts>,
        factors: Arc<dyn SecondFactors>,
        authenticator: Arc<dyn Authenticator>,
    ) -> Self {
        Self {
            origin,
            accounts,
            factors,
            authenticator,
        }
    }

    pub async fn execute(&self, user: UserId) -> Result<Enrollment, AuthError> {
        let account = self
            .accounts
            .by_id(user)
            .await?
            .ok_or(AuthError::UnknownUser)?;
        if account.totp_enabled {
            return Err(AuthError::TotpEnabled);
        }
        let secret = self.authenticator.new_secret();
        self.factors.start_enrollment(user, &secret).await?;
        let issuer = format!("Pina'i ({})", self.origin.domain());
        Ok(Enrollment {
            secret_base32: self.authenticator.base32(&secret),
            provisioning_url: self.authenticator.provisioning_url(
                &secret,
                &issuer,
                &account.email,
            )?,
        })
    }
}

/// `POST /api/totp/enroll/verify`: the app's first code turns the second factor on, with a set of
/// recovery codes shown this once.
pub struct ConfirmTotpEnrollment {
    factors: Arc<dyn SecondFactors>,
    authenticator: Arc<dyn Authenticator>,
}

impl ConfirmTotpEnrollment {
    pub fn new(factors: Arc<dyn SecondFactors>, authenticator: Arc<dyn Authenticator>) -> Self {
        Self {
            factors,
            authenticator,
        }
    }

    pub async fn execute(
        &self,
        user: UserId,
        code: &str,
        now: OffsetDateTime,
    ) -> Result<Vec<String>, AuthError> {
        let secret = self
            .factors
            .pending(user)
            .await?
            .ok_or(AuthError::NoEnrollment)?;
        let step = self
            .authenticator
            .matching_step(&secret, code, now)
            .ok_or(AuthError::WrongCode)?;
        self.factors.enable(user, &secret, step).await
    }
}

#[cfg(test)]
mod tests;
