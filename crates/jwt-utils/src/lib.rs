pub mod issue;
pub mod jwks;
pub mod keys;
pub mod pkce;
pub mod validate;

pub use issue::{issue_access_token, issue_id_token, AccessTokenClaims, IdTokenClaims};
pub use jwks::JwkSet;
pub use keys::{load_ed_keypair_from_pem, EdKeyPair};
pub use pkce::{compute_code_challenge, generate_code_verifier, verify_pkce};
pub use validate::validate_access_token;

#[derive(Debug, thiserror::Error)]
pub enum JwtUtilsError {
    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
    #[error("Key error: {0}")]
    Key(String),
    #[error("PKCE verification failed")]
    PkceVerificationFailed,
}
