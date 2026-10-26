use std::sync::Arc;

use domain::auth::{
    AuthError, INVITATION_RETENTION, Invitations, LoginTickets, RefreshTokens, SESSION_IDLE,
    SESSION_RETENTION, SPENT_RETENTION, Sessions, SignUps, SignupCodes, UNVERIFIED_TTL,
};
use time::OffsetDateTime;

/// What one sweep deleted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Swept {
    pub codes: usize,
    pub tickets: usize,
    pub accounts: usize,
    pub sessions: usize,
    pub refresh_tokens: usize,
    pub invitations: usize,
}

/// Every hour: spent codes and tickets after a day, the accounts never confirmed after a
/// week — freeing their address and name — the sessions a month after they ended, and the
/// refresh tokens left unused as long as a session may idle. A session's other tokens stay
/// while it lives, so a copy presented late is still caught. The invitations go a month after
/// they were used, revoked or expired.
pub struct SweepSignups {
    codes: Arc<dyn SignupCodes>,
    tickets: Arc<dyn LoginTickets>,
    sign_ups: Arc<dyn SignUps>,
    sessions: Arc<dyn Sessions>,
    refresh_tokens: Arc<dyn RefreshTokens>,
    invitations: Arc<dyn Invitations>,
}

impl SweepSignups {
    pub fn new(
        codes: Arc<dyn SignupCodes>,
        tickets: Arc<dyn LoginTickets>,
        sign_ups: Arc<dyn SignUps>,
        sessions: Arc<dyn Sessions>,
        refresh_tokens: Arc<dyn RefreshTokens>,
        invitations: Arc<dyn Invitations>,
    ) -> Self {
        Self {
            codes,
            tickets,
            sign_ups,
            sessions,
            refresh_tokens,
            invitations,
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
            sessions: self.sessions.delete_ended(now - SESSION_RETENTION).await?,
            refresh_tokens: self
                .refresh_tokens
                .delete_unused(now - SESSION_IDLE)
                .await?,
            invitations: self
                .invitations
                .delete_ended(now - INVITATION_RETENTION)
                .await?,
        })
    }
}

#[cfg(test)]
mod tests;
