use std::sync::Arc;

use domain::auth::{
    ACCESS_TOKEN_TTL, AuthError, ClientId, RefreshToken, RefreshTokens, RevokedReason, Rotation,
    SessionNotifier, Sessions, SignInAccounts, TokenIssuer, Tokens,
};
use time::OffsetDateTime;

use super::end_session;

/// `POST /token` with `grant_type=refresh_token`, as it arrived.
#[derive(Debug, Clone)]
pub struct RefreshCommand {
    pub client_id: String,
    pub refresh_token: String,
}

/// A client trades its refresh token for a new access token and the token's successor, its
/// session used once more. A token presented again after its rotation ends the session: whoever
/// holds the other copy is signed out with its owner.
pub struct Refresh {
    refresh_tokens: Arc<dyn RefreshTokens>,
    sessions: Arc<dyn Sessions>,
    notifier: Arc<dyn SessionNotifier>,
    accounts: Arc<dyn SignInAccounts>,
    tokens: Arc<dyn TokenIssuer>,
}

impl Refresh {
    pub fn new(
        refresh_tokens: Arc<dyn RefreshTokens>,
        sessions: Arc<dyn Sessions>,
        notifier: Arc<dyn SessionNotifier>,
        accounts: Arc<dyn SignInAccounts>,
        tokens: Arc<dyn TokenIssuer>,
    ) -> Self {
        Self {
            refresh_tokens,
            sessions,
            notifier,
            accounts,
            tokens,
        }
    }

    pub async fn execute(
        &self,
        command: RefreshCommand,
        now: OffsetDateTime,
    ) -> Result<Tokens, AuthError> {
        let client = ClientId::parse(&command.client_id).map_err(|_| AuthError::UnknownClient)?;
        let rotation = self
            .refresh_tokens
            .rotate(&RefreshToken::new(command.refresh_token), &client, now)
            .await?;
        let (session, successor) = match rotation {
            Rotation::Rotated { session, successor } => (session, successor),
            Rotation::Reused { session } => {
                tracing::warn!(%session, "a rotated refresh token came again: its session ends");
                end_session(
                    &*self.sessions,
                    &*self.notifier,
                    session,
                    RevokedReason::Reuse,
                    now,
                )
                .await?;
                return Err(AuthError::RefreshUnusable);
            }
            Rotation::Refused => return Err(AuthError::RefreshUnusable),
        };
        let session = self
            .sessions
            .find(session)
            .await?
            .filter(|session| session.is_live(now))
            .ok_or(AuthError::RefreshUnusable)?;
        let account = self
            .accounts
            .by_id(session.user)
            .await?
            .ok_or(AuthError::RefreshUnusable)?;
        self.sessions.touch(session.id, now).await?;
        Ok(Tokens {
            access_token: self.tokens.access_token(
                &account,
                session.id,
                &client,
                ACCESS_TOKEN_TTL,
            )?,
            refresh_token: successor,
            id_token: None,
            expires_in: ACCESS_TOKEN_TTL,
        })
    }
}

#[cfg(test)]
mod tests;
