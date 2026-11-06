use std::sync::Arc;

use domain::auth::{AuthError, Authenticator, Enrollment, SecondFactors, Sessions, SignInAccounts};
use domain::e2ee::{DeviceApprovals, may_turn_on_second_factor};
use domain::identity::{Bearer, InstanceOrigin};
use time::OffsetDateTime;

use super::calling_session;

/// The second factor goes on only from an approved device once the account has a history key:
/// identity-provider/specs/auth.md § 3.
async fn may_turn_on(
    sessions: &dyn Sessions,
    approvals: &dyn DeviceApprovals,
    bearer: &Bearer,
) -> Result<(), AuthError> {
    let named = calling_session(sessions, bearer).await?.device;
    let trust = approvals
        .trust(bearer.user)
        .await
        .map_err(|e| AuthError::Unexpected(e.into()))?;
    Ok(may_turn_on_second_factor(named, &trust)?)
}

/// `POST /api/totp/enroll`: a fresh secret for the account's authenticator app, kept aside until
/// a first code confirms it.
pub struct StartTotpEnrollment {
    origin: InstanceOrigin,
    accounts: Arc<dyn SignInAccounts>,
    factors: Arc<dyn SecondFactors>,
    authenticator: Arc<dyn Authenticator>,
    sessions: Arc<dyn Sessions>,
    approvals: Arc<dyn DeviceApprovals>,
}

impl StartTotpEnrollment {
    pub fn new(
        origin: InstanceOrigin,
        accounts: Arc<dyn SignInAccounts>,
        factors: Arc<dyn SecondFactors>,
        authenticator: Arc<dyn Authenticator>,
        sessions: Arc<dyn Sessions>,
        approvals: Arc<dyn DeviceApprovals>,
    ) -> Self {
        Self {
            origin,
            accounts,
            factors,
            authenticator,
            sessions,
            approvals,
        }
    }

    pub async fn execute(&self, bearer: &Bearer) -> Result<Enrollment, AuthError> {
        may_turn_on(&*self.sessions, &*self.approvals, bearer).await?;
        let user = bearer.user;
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
    sessions: Arc<dyn Sessions>,
    approvals: Arc<dyn DeviceApprovals>,
}

impl ConfirmTotpEnrollment {
    pub fn new(
        factors: Arc<dyn SecondFactors>,
        authenticator: Arc<dyn Authenticator>,
        sessions: Arc<dyn Sessions>,
        approvals: Arc<dyn DeviceApprovals>,
    ) -> Self {
        Self {
            factors,
            authenticator,
            sessions,
            approvals,
        }
    }

    /// Asked again here: what turns the second factor on is this code, not the enrollment.
    pub async fn execute(
        &self,
        bearer: &Bearer,
        code: &str,
        now: OffsetDateTime,
    ) -> Result<Vec<String>, AuthError> {
        may_turn_on(&*self.sessions, &*self.approvals, bearer).await?;
        let user = bearer.user;
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
