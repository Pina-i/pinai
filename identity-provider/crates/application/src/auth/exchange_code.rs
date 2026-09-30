use std::sync::Arc;

use domain::auth::{
    ACCESS_TOKEN_TTL, AuthError, AuthorizationCode, AuthorizationCodes, ClientId, Clients,
    GRANT_TYPE, SignInAccounts, TokenIssuer, Tokens,
};
use time::OffsetDateTime;

/// `POST /token`, as it arrived.
#[derive(Debug, Clone)]
pub struct TokenCommand {
    pub grant_type: String,
    pub code: String,
    pub redirect_uri: String,
    pub client_id: String,
    pub code_verifier: String,
}

/// A client trades the code a sign-in ended in for the account's tokens — once.
pub struct ExchangeCode {
    clients: Arc<dyn Clients>,
    codes: Arc<dyn AuthorizationCodes>,
    accounts: Arc<dyn SignInAccounts>,
    tokens: Arc<dyn TokenIssuer>,
}

impl ExchangeCode {
    pub fn new(
        clients: Arc<dyn Clients>,
        codes: Arc<dyn AuthorizationCodes>,
        accounts: Arc<dyn SignInAccounts>,
        tokens: Arc<dyn TokenIssuer>,
    ) -> Self {
        Self {
            clients,
            codes,
            accounts,
            tokens,
        }
    }

    pub async fn execute(
        &self,
        command: TokenCommand,
        now: OffsetDateTime,
    ) -> Result<Tokens, AuthError> {
        if command.grant_type != GRANT_TYPE {
            return Err(AuthError::UnsupportedGrantType);
        }
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
        self.tokens.issue(
            &account,
            &client.id,
            grant.nonce.as_deref(),
            ACCESS_TOKEN_TTL,
        )
    }
}

#[cfg(test)]
mod tests;
