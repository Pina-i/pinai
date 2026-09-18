use jsonwebtoken::{encode, Algorithm, Header};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::{EdKeyPair, JwtUtilsError};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AccessTokenClaims {
    pub iss: String,
    pub sub: String,               // user UUID as string
    pub aud: String,               // client_id
    pub exp: i64,                  // unix timestamp
    pub iat: i64,
    pub email: String,
    pub preferred_username: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IdTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub email: String,
    pub preferred_username: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

pub fn issue_access_token(
    keypair: &EdKeyPair,
    issuer: &str,
    subject: &str,    // user UUID
    audience: &str,   // client_id
    email: &str,
    username: &str,
    ttl_seconds: i64,
) -> Result<String, JwtUtilsError> {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let claims = AccessTokenClaims {
        iss: issuer.to_owned(),
        sub: subject.to_owned(),
        aud: audience.to_owned(),
        exp: now + ttl_seconds,
        iat: now,
        email: email.to_owned(),
        preferred_username: username.to_owned(),
    };

    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(keypair.kid.clone());

    encode(&header, &claims, &keypair.encoding_key).map_err(JwtUtilsError::Jwt)
}

pub fn issue_id_token(
    keypair: &EdKeyPair,
    issuer: &str,
    subject: &str,
    audience: &str,
    email: &str,
    username: &str,
    nonce: Option<String>,
    ttl_seconds: i64,
) -> Result<String, JwtUtilsError> {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let claims = IdTokenClaims {
        iss: issuer.to_owned(),
        sub: subject.to_owned(),
        aud: audience.to_owned(),
        exp: now + ttl_seconds,
        iat: now,
        email: email.to_owned(),
        preferred_username: username.to_owned(),
        nonce,
    };

    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(keypair.kid.clone());

    encode(&header, &claims, &keypair.encoding_key).map_err(JwtUtilsError::Jwt)
}
