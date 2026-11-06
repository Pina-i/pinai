use std::sync::Arc;

use domain::auth::{AuthError, SessionNotifier, Sessions};
use domain::e2ee::{DeviceApprovals, may_act_beyond_the_password};
use domain::identity::Bearer;
use time::OffsetDateTime;

use super::{calling_trust, tell_ended};

/// `DELETE /api/sessions?keep=current`: every other session of the account ends — other
/// browsers, other apps, this browser's other web apps — their tokens and sockets with them. The
/// caller's stays, with the browser session it hangs under. Once the account has a history key,
/// only from an approved device: identity-provider/specs/auth.md § 1 "Sessions and devices".
pub struct SignOutOthers {
    sessions: Arc<dyn Sessions>,
    approvals: Arc<dyn DeviceApprovals>,
    notifier: Arc<dyn SessionNotifier>,
}

impl SignOutOthers {
    pub fn new(
        sessions: Arc<dyn Sessions>,
        approvals: Arc<dyn DeviceApprovals>,
        notifier: Arc<dyn SessionNotifier>,
    ) -> Self {
        Self {
            sessions,
            approvals,
            notifier,
        }
    }

    /// How many ended.
    pub async fn execute(&self, bearer: Bearer, now: OffsetDateTime) -> Result<usize, AuthError> {
        let (named, trust) = calling_trust(&*self.sessions, &*self.approvals, &bearer).await?;
        may_act_beyond_the_password(named, &trust)?;
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
