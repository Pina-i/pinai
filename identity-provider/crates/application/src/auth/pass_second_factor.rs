use std::sync::Arc;

use domain::auth::{
    AuthError, Authenticator, AuthorizationCode, AuthorizationCodes, AuthorizationRequest,
    ClientSignIns, LoginTickets, SecondFactors, TICKET_ATTEMPTS, TicketAttempt,
};
use domain::{TicketId, UserId};
use time::OffsetDateTime;

use super::signed_in;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecondFactorOutcome {
    SignedIn {
        user: UserId,
        request: AuthorizationRequest,
        code: AuthorizationCode,
    },
    /// No such open ticket: the sign-in starts again.
    Expired,
    /// The ticket had its guesses: the password step must be cleared again.
    TooManyAttempts,
    WrongCode,
    UnknownRecoveryCode,
    /// Neither a code nor a recovery code.
    Missing,
    /// Spent by another request meanwhile.
    AlreadyUsed,
}

/// `POST /login/totp`: the authenticator's code, or a recovery code, for the ticket the password
/// step opened.
pub struct PassSecondFactor {
    tickets: Arc<dyn LoginTickets>,
    factors: Arc<dyn SecondFactors>,
    authenticator: Arc<dyn Authenticator>,
    codes: Arc<dyn AuthorizationCodes>,
    sign_ins: Arc<dyn ClientSignIns>,
}

impl PassSecondFactor {
    pub fn new(
        tickets: Arc<dyn LoginTickets>,
        factors: Arc<dyn SecondFactors>,
        authenticator: Arc<dyn Authenticator>,
        codes: Arc<dyn AuthorizationCodes>,
        sign_ins: Arc<dyn ClientSignIns>,
    ) -> Self {
        Self {
            tickets,
            factors,
            authenticator,
            codes,
            sign_ins,
        }
    }

    pub async fn execute(
        &self,
        ticket: TicketId,
        code: Option<&str>,
        recovery_code: Option<&str>,
        now: OffsetDateTime,
    ) -> Result<SecondFactorOutcome, AuthError> {
        let given =
            |value: Option<&str>| value.filter(|value| !value.is_empty()).map(str::to_owned);
        let (code, recovery_code) = (given(code), given(recovery_code));
        if code.is_none() && recovery_code.is_none() {
            // Nothing sent is not a guess, and is not counted.
            return Ok(match self.tickets.find(ticket, now).await? {
                None => SecondFactorOutcome::Expired,
                Some(open) if open.attempts >= TICKET_ATTEMPTS => {
                    SecondFactorOutcome::TooManyAttempts
                }
                Some(_) => SecondFactorOutcome::Missing,
            });
        }
        let open = match self.tickets.reserve_attempt(ticket, now).await? {
            TicketAttempt::Open(open) => open,
            TicketAttempt::Exhausted => return Ok(SecondFactorOutcome::TooManyAttempts),
            TicketAttempt::Gone => return Ok(SecondFactorOutcome::Expired),
        };
        let secret = self.factors.secret(open.user).await?.ok_or_else(|| {
            anyhow::anyhow!("a login ticket for an account without a second factor")
        })?;
        if let Some(code) = code {
            // A code is good once: seen again, even within its window, it is refused.
            let used = match self.authenticator.matching_step(&secret, &code, now) {
                Some(step) => self.factors.use_step(open.user, step).await?,
                None => false,
            };
            if !used {
                return Ok(SecondFactorOutcome::WrongCode);
            }
        } else if let Some(recovery_code) = recovery_code
            && !self
                .factors
                .use_recovery_code(open.user, &recovery_code)
                .await?
        {
            return Ok(SecondFactorOutcome::UnknownRecoveryCode);
        }
        if !self.tickets.consume(ticket).await? {
            return Ok(SecondFactorOutcome::AlreadyUsed);
        }
        let code = signed_in(&*self.sign_ins, &*self.codes, open.user, &open.request, now).await?;
        Ok(SecondFactorOutcome::SignedIn {
            user: open.user,
            request: open.request,
            code,
        })
    }
}

#[cfg(test)]
mod tests;
