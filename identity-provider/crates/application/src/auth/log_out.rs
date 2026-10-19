use std::sync::Arc;

use domain::SessionId;
use domain::auth::{AuthError, ClientId, Clients, RevokedReason, SessionNotifier, Sessions};
use time::OffsetDateTime;

use super::end_session;

/// `GET /logout`: the browser's session ends — every token it led to with it — and the browser
/// goes back where its client asked if the client listed that place.
pub struct LogOut {
    clients: Arc<dyn Clients>,
    sessions: Arc<dyn Sessions>,
    notifier: Arc<dyn SessionNotifier>,
}

impl LogOut {
    pub fn new(
        clients: Arc<dyn Clients>,
        sessions: Arc<dyn Sessions>,
        notifier: Arc<dyn SessionNotifier>,
    ) -> Self {
        Self {
            clients,
            sessions,
            notifier,
        }
    }

    /// Where to send the browser; `None` for this instance's signed-out page.
    pub async fn execute(
        &self,
        session: Option<SessionId>,
        client: Option<&str>,
        return_to: Option<&str>,
        now: OffsetDateTime,
    ) -> Result<Option<String>, AuthError> {
        if let Some(session) = session {
            end_session(
                &*self.sessions,
                &*self.notifier,
                session,
                RevokedReason::SignOut,
                now,
            )
            .await?;
        }
        let (Some(client), Some(uri)) = (client, return_to) else {
            return Ok(None);
        };
        let listed = match ClientId::parse(client) {
            Ok(id) => self
                .clients
                .find(&id)
                .await?
                .is_some_and(|client| client.may_return_to(uri)),
            Err(_) => false,
        };
        if !listed {
            tracing::warn!(client, uri, "post-logout redirect refused");
            return Ok(None);
        }
        Ok(Some(uri.to_owned()))
    }
}

#[cfg(test)]
mod tests;
