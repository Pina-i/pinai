use std::sync::Arc;

use domain::auth::{AuthError, SessionNotifier, Sessions};
use domain::identity::Bearer;
use time::OffsetDateTime;

use super::tell_ended;

/// `DELETE /api/sessions?keep=current`: every other session of the account ends — other
/// browsers, other apps — their tokens and sockets with them. The caller's stays.
pub struct SignOutOthers {
    sessions: Arc<dyn Sessions>,
    notifier: Arc<dyn SessionNotifier>,
}

impl SignOutOthers {
    pub fn new(sessions: Arc<dyn Sessions>, notifier: Arc<dyn SessionNotifier>) -> Self {
        Self { sessions, notifier }
    }

    /// How many ended.
    pub async fn execute(&self, bearer: Bearer, now: OffsetDateTime) -> Result<usize, AuthError> {
        let ended = self
            .sessions
            .revoke_others(bearer.user, bearer.session, now)
            .await?;
        tell_ended(&*self.notifier, &ended);
        Ok(ended.len())
    }
}

#[cfg(test)]
mod tests;
