use std::sync::Arc;

use domain::SessionId;
use domain::auth::{
    AuthError, AuthorizationCode, AuthorizationCodes, AuthorizationRequest, CODE_TTL, ClientId,
    ClientSignIns, Clients, CodeChallenge, Grant, RESPONSE_TYPE, Sessions, SignInAccounts,
    prompts_login,
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
    pub prompt: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Authorized {
    /// Signed in already, to this app: back to it with a code, the session used once more.
    Code {
        request: AuthorizationRequest,
        code: AuthorizationCode,
        session: SessionId,
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
    sessions: Arc<dyn Sessions>,
}

impl Authorize {
    pub fn new(
        clients: Arc<dyn Clients>,
        accounts: Arc<dyn SignInAccounts>,
        codes: Arc<dyn AuthorizationCodes>,
        sign_ins: Arc<dyn ClientSignIns>,
        sessions: Arc<dyn Sessions>,
    ) -> Self {
        Self {
            clients,
            accounts,
            codes,
            sign_ins,
            sessions,
        }
    }

    pub async fn execute(
        &self,
        command: AuthorizeCommand,
        session: Option<SessionId>,
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
        let asks_login = prompts_login(command.prompt.as_deref());
        let request = AuthorizationRequest {
            client: client.id,
            redirect_uri: command.redirect_uri,
            scope: command.scope,
            state: command.state,
            challenge,
            nonce: command.nonce,
        };
        if asks_login {
            return Ok(Authorized::SignIn(request));
        }
        // A cookie naming a session that isn't live any more is no cookie at all.
        let session = match session {
            Some(id) => self.sessions.find(id).await?,
            None => None,
        };
        let Some(session) = session.filter(|session| session.is_live(now)) else {
            return Ok(Authorized::SignIn(request));
        };
        if self.accounts.by_id(session.user).await?.is_none() {
            return Ok(Authorized::SignIn(request));
        }
        let known = self.sign_ins.find(session.user, &request.client).await?;
        if !known.is_some_and(|known| known.covers(&request)) {
            return Ok(Authorized::SignIn(request));
        }
        self.sessions.touch(session.id, now).await?;
        let code = self
            .codes
            .issue(
                &Grant::answering(session.user, session.id, &request),
                now + CODE_TTL,
            )
            .await?;
        Ok(Authorized::Code {
            request,
            code,
            session: session.id,
        })
    }
}

#[cfg(test)]
mod tests;
