use std::sync::Arc;

use domain::auth::Sessions;
use domain::identity::{Bearer, TokenError, TokenVerifier};
use time::OffsetDateTime;

/// A bearer token, for every authenticated request and the WebSocket: its signature and expiry,
/// then its session — so a session ended signs its tokens out at once, not an hour later.
pub struct Authenticate {
    tokens: Arc<dyn TokenVerifier>,
    sessions: Arc<dyn Sessions>,
}

impl Authenticate {
    pub fn new(tokens: Arc<dyn TokenVerifier>, sessions: Arc<dyn Sessions>) -> Self {
        Self { tokens, sessions }
    }

    pub async fn execute(&self, token: &str, now: OffsetDateTime) -> Result<Bearer, TokenError> {
        let bearer = self.tokens.verify(token)?;
        let session = self
            .sessions
            .find(bearer.session)
            .await
            .map_err(|e| TokenError::Unexpected(anyhow::Error::from(e)))?;
        match session {
            Some(session) if session.user == bearer.user && session.is_live(now) => Ok(bearer),
            _ => Err(TokenError::SessionEnded),
        }
    }
}

#[cfg(test)]
mod tests;
