use std::sync::Arc;

use domain::auth::{
    ACCESS_TOKEN_TTL, AuthError, AuthorizationCode, AuthorizationCodes, ClientId, Clients,
    RefreshTokens, SessionKind, Sessions, SignInAccounts, TokenIssuer, Tokens,
};
use time::OffsetDateTime;

/// `POST /token` with `grant_type=authorization_code`, as it arrived.
#[derive(Debug, Clone)]
pub struct TokenCommand {
    pub code: String,
    pub redirect_uri: String,
    pub client_id: String,
    pub code_verifier: String,
}

/// A client trades the code a sign-in ended in for the account's tokens — once. The refresh
/// token starts a chain under the browser's session, or under a session of the app's own when
/// it stays signed in on its device.
pub struct ExchangeCode {
    clients: Arc<dyn Clients>,
    codes: Arc<dyn AuthorizationCodes>,
    accounts: Arc<dyn SignInAccounts>,
    tokens: Arc<dyn TokenIssuer>,
    sessions: Arc<dyn Sessions>,
    refresh_tokens: Arc<dyn RefreshTokens>,
}

impl ExchangeCode {
    pub fn new(
        clients: Arc<dyn Clients>,
        codes: Arc<dyn AuthorizationCodes>,
        accounts: Arc<dyn SignInAccounts>,
        tokens: Arc<dyn TokenIssuer>,
        sessions: Arc<dyn Sessions>,
        refresh_tokens: Arc<dyn RefreshTokens>,
    ) -> Self {
        Self {
            clients,
            codes,
            accounts,
            tokens,
            sessions,
            refresh_tokens,
        }
    }

    pub async fn execute(
        &self,
        command: TokenCommand,
        now: OffsetDateTime,
    ) -> Result<Tokens, AuthError> {
        let client_id =
            ClientId::parse(&command.client_id).map_err(|_| AuthError::UnknownClient)?;
        let client = self
            .clients
            .find(&client_id)
            .await?
            .ok_or(AuthError::UnknownClient)?;
        if !client.allows(&command.redirect_uri) {
            return Err(AuthError::RedirectMismatch);
        }
        // Spent before the checks below: a code presented wrongly is never tried again.
        let grant = self
            .codes
            .consume(&AuthorizationCode::new(command.code), now)
            .await?
            .ok_or(AuthError::CodeUnusable)?;
        if grant.client != client.id {
            return Err(AuthError::ClientMismatch);
        }
        if grant.redirect_uri != command.redirect_uri {
            return Err(AuthError::RedirectMismatch);
        }
        if !grant.challenge.is_met_by(&command.code_verifier) {
            return Err(AuthError::VerifierMismatch);
        }
        let account = self
            .accounts
            .by_id(grant.user)
            .await?
            .ok_or(AuthError::CodeUnusable)?;
        // Signed out between the code and its exchange: the code goes with its session.
        let browser = self
            .sessions
            .find(grant.session)
            .await?
            .filter(|session| session.is_live(now))
            .ok_or(AuthError::CodeUnusable)?;
        let session = if grant.opens_app_session(&client) {
            let app = self
                .sessions
                .open(account.id, &SessionKind::App(client.id.clone()), now)
                .await?;
            // Opened by the password typed on the browser's session: as recent as that, no more.
            self.sessions
                .authenticate(app, browser.authenticated_at)
                .await?;
            self.sessions
                .find(app)
                .await?
                .ok_or_else(|| anyhow::anyhow!("the app session just opened is gone"))?
        } else {
            browser
        };
        Ok(Tokens {
            access_token: self.tokens.access_token(
                &account,
                &session,
                &client.id,
                ACCESS_TOKEN_TTL,
            )?,
            refresh_token: self
                .refresh_tokens
                .start(session.id, &client.id, now)
                .await?,
            id_token: Some(self.tokens.id_token(
                &account,
                &client.id,
                grant.nonce.as_deref(),
                ACCESS_TOKEN_TTL,
            )?),
            expires_in: ACCESS_TOKEN_TTL,
        })
    }
}

#[cfg(test)]
mod tests;
