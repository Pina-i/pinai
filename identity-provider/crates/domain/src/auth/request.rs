use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use time::Duration;

use crate::{UserId, ValidationError};

use super::{AuthError, ClientId};

/// The only flow: authorization code with PKCE.
pub const RESPONSE_TYPE: &str = "code";
pub const GRANT_TYPE: &str = "authorization_code";

pub const CODE_TTL: Duration = Duration::minutes(10);
pub const ACCESS_TOKEN_TTL: Duration = Duration::hours(1);
/// Long enough to find a phone, short enough that a stolen ticket can't linger.
pub const LOGIN_TICKET_TTL: Duration = Duration::minutes(5);
pub const SIGNUP_CODE_TTL: Duration = Duration::minutes(10);

/// A PKCE challenge — RFC 7636.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeChallenge(String);

impl CodeChallenge {
    /// S256 only: with `plain`, whoever reads the request holds the verifier.
    pub fn parse(challenge: &str, method: &str) -> Result<Self, AuthError> {
        if method != "S256" {
            return Err(AuthError::BadChallengeMethod);
        }
        Ok(Self(challenge.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// `BASE64URL(SHA256(verifier))` is the challenge, compared in constant time.
    pub fn is_met_by(&self, verifier: &str) -> bool {
        let computed = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        computed.len() == self.0.len()
            && computed
                .bytes()
                .zip(self.0.bytes())
                .fold(0, |diff, (a, b)| diff | (a ^ b))
                == 0
    }
}

/// What a client asks for when it sends a user to sign in: carried through the sign-in pages,
/// and kept with the code the sign-in ends in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationRequest {
    pub client: ClientId,
    pub redirect_uri: String,
    pub scope: String,
    /// The client's own value, handed back with the code.
    pub state: String,
    pub challenge: CodeChallenge,
    pub nonce: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuthorizationCode(String);

impl AuthorizationCode {
    pub fn new(code: String) -> Self {
        Self(code)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// What a code stands for: who signed in, for which client, and what the exchange must match.
/// The request's `state` is not kept — it went back with the code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub user: UserId,
    pub client: ClientId,
    pub redirect_uri: String,
    pub scope: String,
    pub challenge: CodeChallenge,
    pub nonce: Option<String>,
}

impl Grant {
    pub fn answering(user: UserId, request: &AuthorizationRequest) -> Self {
        Self {
            user,
            client: request.client.clone(),
            redirect_uri: request.redirect_uri.clone(),
            scope: request.scope.clone(),
            challenge: request.challenge.clone(),
            nonce: request.nonce.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tokens {
    pub access_token: String,
    pub id_token: String,
    pub expires_in: Duration,
}

/// The six digits mailed to confirm an address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtpCode(String);

impl OtpCode {
    pub const LEN: usize = 6;

    pub fn parse(raw: &str) -> Result<Self, ValidationError> {
        if raw.len() == Self::LEN && raw.chars().all(|c| c.is_ascii_digit()) {
            Ok(Self(raw.to_owned()))
        } else {
            Err(ValidationError::new("code", "6 digits"))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests;
