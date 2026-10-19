use std::sync::Arc;

use domain::UserId;
use domain::auth::{
    AuthError, AuthorizationCode, AuthorizationCodes, AuthorizationRequest, CODE_TTL, ClientId,
    ClientSignIns, Clients, CodeChallenge, Grant, RESPONSE_TYPE, SignInAccounts,
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
    /// Signed in already, to this app: back to it with a code.
    Code {
        request: AuthorizationRequest,
        code: AuthorizationCode,
    },
    /// To the sign-in pages, carrying the request.
    SignIn(AuthorizationRequest),
}

/// A client sends a browser to sign in. One with a session here is handed a code at once, for
/// an app its account signed in to with the password; any other app asks the password first,
/// or any site could take a code by sending the browser here.
pub struct Authorize {
    clients: Arc<dyn Clients>,
    accounts: Arc<dyn SignInAccounts>,
    codes: Arc<dyn AuthorizationCodes>,
    sign_ins: Arc<dyn ClientSignIns>,
}

impl Authorize {
    pub fn new(
        clients: Arc<dyn Clients>,
        accounts: Arc<dyn SignInAccounts>,
        codes: Arc<dyn AuthorizationCodes>,
        sign_ins: Arc<dyn ClientSignIns>,
    ) -> Self {
        Self {
            clients,
            accounts,
            codes,
            sign_ins,
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
        let known = self.sign_ins.find(account.id, &request.client).await?;
        if !known.is_some_and(|known| known.covers(&request)) {
            return Ok(Authorized::SignIn(request));
        }
        let code = self
            .codes
            .issue(&Grant::answering(account.id, &request), now + CODE_TTL)
            .await?;
        Ok(Authorized::Code { request, code })
    }
}

#[cfg(test)]
mod tests;
