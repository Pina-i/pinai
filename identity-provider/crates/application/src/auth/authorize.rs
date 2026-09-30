use std::sync::Arc;

use domain::UserId;
use domain::auth::{
    AuthError, AuthorizationCode, AuthorizationCodes, AuthorizationRequest, CODE_TTL, ClientId,
    Clients, CodeChallenge, Grant, RESPONSE_TYPE, SignInAccounts,
};
use time::OffsetDateTime;

/// `GET /authorize`, as it arrived.
#[derive(Debug, Clone)]
pub struct AuthorizeCommand {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub state: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub nonce: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Authorized {
    /// Signed in already: back to the client with a code.
    Code {
        request: AuthorizationRequest,
        code: AuthorizationCode,
    },
    /// To the sign-in pages, carrying the request.
    SignIn(AuthorizationRequest),
}

/// A client sends a browser to sign in; one with a session here is handed a code at once.
pub struct Authorize {
    clients: Arc<dyn Clients>,
    accounts: Arc<dyn SignInAccounts>,
    codes: Arc<dyn AuthorizationCodes>,
}

impl Authorize {
    pub fn new(
        clients: Arc<dyn Clients>,
        accounts: Arc<dyn SignInAccounts>,
        codes: Arc<dyn AuthorizationCodes>,
    ) -> Self {
        Self {
            clients,
            accounts,
            codes,
        }
    }

    pub async fn execute(
        &self,
        command: AuthorizeCommand,
        session: Option<UserId>,
        now: OffsetDateTime,
    ) -> Result<Authorized, AuthError> {
        // The client and its redirect first: once they are known good, the errors that follow
        // are sent back to the client rather than shown here — RFC 6749 § 4.1.2.1.
        let client_id =
            ClientId::parse(&command.client_id).map_err(|_| AuthError::UnknownClient)?;
        let client = self
            .clients
            .find(&client_id)
            .await?
            .ok_or(AuthError::UnknownClient)?;
        if !client.allows(&command.redirect_uri) {
            return Err(AuthError::UnregisteredRedirect);
        }
        if command.response_type != RESPONSE_TYPE {
            return Err(AuthError::UnsupportedResponseType);
        }
        let challenge =
            CodeChallenge::parse(&command.code_challenge, &command.code_challenge_method)?;
        let request = AuthorizationRequest {
            client: client.id,
            redirect_uri: command.redirect_uri,
            scope: command.scope,
            state: command.state,
            challenge,
            nonce: command.nonce,
        };
        let signed_in = match session {
            Some(user) => self.accounts.by_id(user).await?,
            None => None,
        };
        let Some(account) = signed_in else {
            return Ok(Authorized::SignIn(request));
        };
        let code = self
            .codes
            .issue(&Grant::answering(account.id, &request), now + CODE_TTL)
            .await?;
        Ok(Authorized::Code { request, code })
    }
}

#[cfg(test)]
mod tests;
