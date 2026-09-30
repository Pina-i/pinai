use std::sync::Arc;

use domain::auth::{
    AuthError, LoginTickets, SPENT_RETENTION, SignUps, SignupCodes, UNVERIFIED_TTL,
};
use time::OffsetDateTime;

/// What one sweep deleted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Swept {
    pub codes: usize,
    pub tickets: usize,
    pub accounts: usize,
}

/// Every hour: spent codes and tickets after a day, and the accounts never confirmed after a
/// week — freeing their address and name.
pub struct SweepSignups {
    codes: Arc<dyn SignupCodes>,
    tickets: Arc<dyn LoginTickets>,
    sign_ups: Arc<dyn SignUps>,
}

impl SweepSignups {
    pub fn new(
        codes: Arc<dyn SignupCodes>,
        tickets: Arc<dyn LoginTickets>,
        sign_ups: Arc<dyn SignUps>,
    ) -> Self {
        Self {
            codes,
            tickets,
            sign_ups,
        }
    }

    pub async fn execute(&self, now: OffsetDateTime) -> Result<Swept, AuthError> {
        Ok(Swept {
            codes: self.codes.delete_spent(now, now - SPENT_RETENTION).await?,
            tickets: self
                .tickets
                .delete_spent(now, now - SPENT_RETENTION)
                .await?,
            accounts: self
                .sign_ups
                .delete_unverified(now - UNVERIFIED_TTL)
                .await?,
        })
    }
}

#[cfg(test)]
mod tests;
