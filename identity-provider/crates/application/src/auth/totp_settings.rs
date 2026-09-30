use std::sync::Arc;

use domain::UserId;
use domain::auth::{AuthError, Authenticator, SecondFactors, SignInAccounts, TotpSecret};
use time::OffsetDateTime;

/// The secret of an account whose second factor is on, once `code` proves the app is at hand: a
/// passive session cannot disarm it.
async fn proven(
    accounts: &dyn SignInAccounts,
    factors: &dyn SecondFactors,
    authenticator: &dyn Authenticator,
    user: UserId,
    code: &str,
    now: OffsetDateTime,
) -> Result<TotpSecret, AuthError> {
    let account = accounts.by_id(user).await?.ok_or(AuthError::UnknownUser)?;
    if !account.totp_enabled {
        return Err(AuthError::TotpNotEnabled);
    }
    let secret = factors
        .secret(user)
        .await?
        .ok_or_else(|| anyhow::anyhow!("a second factor on without its secret"))?;
    // A code is good once: the one that signed in cannot also disarm the second factor.
    let used = match authenticator.matching_step(&secret, code, now) {
        Some(step) => factors.use_step(user, step).await?,
        None => false,
    };
    if !used {
        return Err(AuthError::WrongCode);
    }
    Ok(secret)
}

/// `POST /api/totp/disable`: the second factor off, its secret, recovery codes and any enrollment
/// forgotten.
pub struct DisableTotp {
    accounts: Arc<dyn SignInAccounts>,
    factors: Arc<dyn SecondFactors>,
    authenticator: Arc<dyn Authenticator>,
}

impl DisableTotp {
    pub fn new(
        accounts: Arc<dyn SignInAccounts>,
        factors: Arc<dyn SecondFactors>,
        authenticator: Arc<dyn Authenticator>,
    ) -> Self {
        Self {
            accounts,
            factors,
            authenticator,
        }
    }

    pub async fn execute(
        &self,
        user: UserId,
        code: &str,
        now: OffsetDateTime,
    ) -> Result<(), AuthError> {
        proven(
            &*self.accounts,
            &*self.factors,
            &*self.authenticator,
            user,
            code,
            now,
        )
        .await?;
        self.factors.disable(user).await
    }
}

/// `POST /api/totp/recovery-codes/regenerate`: a new set of recovery codes, the old ones void.
pub struct RegenerateRecoveryCodes {
    accounts: Arc<dyn SignInAccounts>,
    factors: Arc<dyn SecondFactors>,
    authenticator: Arc<dyn Authenticator>,
}

impl RegenerateRecoveryCodes {
    pub fn new(
        accounts: Arc<dyn SignInAccounts>,
        factors: Arc<dyn SecondFactors>,
        authenticator: Arc<dyn Authenticator>,
    ) -> Self {
        Self {
            accounts,
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
        proven(
            &*self.accounts,
            &*self.factors,
            &*self.authenticator,
            user,
            code,
            now,
        )
        .await?;
        self.factors.replace_recovery_codes(user).await
    }
}

#[cfg(test)]
mod tests;
