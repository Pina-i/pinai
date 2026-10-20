use std::sync::Arc;

use domain::auth::{
    AuthError, ClientId, RefreshToken, RefreshTokens, RevokedReason, SessionNotifier, Sessions,
};
use time::OffsetDateTime;

use super::end_session;

/// `POST /revoke` (RFC 7009): an app signs out by revoking its refresh token, and its session
/// ends — every token of it, and its sockets. A token unknown here, or another client's, changes
/// nothing and is answered alike: the endpoint tells nothing of tokens.
pub struct RevokeToken {
    refresh_tokens: Arc<dyn RefreshTokens>,
    sessions: Arc<dyn Sessions>,
    notifier: Arc<dyn SessionNotifier>,
}

impl RevokeToken {
    pub fn new(
        refresh_tokens: Arc<dyn RefreshTokens>,
        sessions: Arc<dyn Sessions>,
        notifier: Arc<dyn SessionNotifier>,
    ) -> Self {
        Self {
            refresh_tokens,
            sessions,
            notifier,
        }
    }

    pub async fn execute(
        &self,
        client_id: &str,
        token: &str,
        now: OffsetDateTime,
    ) -> Result<(), AuthError> {
        let client = ClientId::parse(client_id).map_err(|_| AuthError::UnknownClient)?;
        let session = self
            .refresh_tokens
            .session_of(&RefreshToken::new(token.to_owned()), &client)
            .await?;
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
        Ok(())
    }
}

#[cfg(test)]
mod tests;
