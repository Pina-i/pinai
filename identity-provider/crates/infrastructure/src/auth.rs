//! Access tokens this instance issued for the web client.

use std::sync::Arc;

use domain::UserId;
use domain::identity::{TokenError, TokenVerifier};
use jwt_utils::{EdKeyPair, validate_access_token};

pub struct JwtTokenVerifier {
    keypair: Arc<EdKeyPair>,
    issuer: String,
}

impl JwtTokenVerifier {
    pub fn new(keypair: Arc<EdKeyPair>, issuer: String) -> Self {
        Self { keypair, issuer }
    }
}

impl TokenVerifier for JwtTokenVerifier {
    fn verify(&self, token: &str) -> Result<UserId, TokenError> {
        let claims = validate_access_token(token, &self.keypair, &self.issuer, "web-client")
            .map_err(|_| TokenError::Invalid)?;
        claims
            .sub
            .parse::<uuid::Uuid>()
            .map(UserId::from)
            .map_err(|_| TokenError::BadSubject)
    }
}

#[cfg(test)]
mod tests;
