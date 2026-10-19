use std::sync::Arc;

use connections::Hub;
use domain::auth::{Session, SessionNotifier};

/// Closes the account's sockets opened under a session that ended: a signed-out browser's tabs
/// stop receiving at once, not when their token expires.
pub struct HubSessionNotifier {
    hub: Arc<Hub>,
}

impl HubSessionNotifier {
    pub fn new(hub: Arc<Hub>) -> Self {
        Self { hub }
    }
}

impl SessionNotifier for HubSessionNotifier {
    fn ended(&self, session: &Session) {
        self.hub
            .end_session(&session.user.as_uuid(), &session.id.as_uuid());
    }
}

#[cfg(test)]
mod tests;
