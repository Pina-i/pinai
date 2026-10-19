//! Tokens this instance issues and checks, the password check, and the clients it signs in to.

mod clients;

pub use clients::MetadataClients;

use std::sync::Arc;

use anyhow::Context;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHasher as _, PasswordVerifier};
use domain::auth::{
    AuthError, Authenticator, ClientId, HandleSuffixes, PasswordHash, PasswordHasher,
    SignInAccount, TokenIssuer, TotpSecret,
};
use domain::identity::{Bearer, HandleSuffix, TokenError, TokenVerifier};
use domain::{SessionId, UserId};
use jwt_utils::{EdKeyPair, issue_access_token, issue_id_token, validate_access_token};
use rand::rngs::OsRng;
use rand::{Rng, RngCore};
use time::{Duration, OffsetDateTime};
use totp_rs::{Algorithm, TOTP};

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
    fn verify(&self, token: &str) -> Result<Bearer, TokenError> {
        // RFC 9068: an access token is addressed to this instance's API, whichever client holds it.
        let claims = validate_access_token(token, &self.keypair, &self.issuer, &self.issuer)
            .map_err(|_| TokenError::Invalid)?;
        let user = claims
            .sub
            .parse::<uuid::Uuid>()
            .map(UserId::from)
            .map_err(|_| TokenError::BadSubject)?;
        let session = claims
            .sid
            .parse::<uuid::Uuid>()
            .map(SessionId::from)
            .map_err(|_| TokenError::Invalid)?;
        Ok(Bearer { user, session })
    }
}

/// Access and ID tokens, signed with the instance's key: the one its JWKS publishes.
pub struct JwtTokenIssuer {
    keypair: Arc<EdKeyPair>,
    issuer: String,
}

impl JwtTokenIssuer {
    pub fn new(keypair: Arc<EdKeyPair>, issuer: String) -> Self {
        Self { keypair, issuer }
    }
}

impl TokenIssuer for JwtTokenIssuer {
    fn access_token(
        &self,
        account: &SignInAccount,
        session: SessionId,
        client: &ClientId,
        ttl: Duration,
    ) -> Result<String, AuthError> {
        Ok(issue_access_token(
            &self.keypair,
            &self.issuer,
            &account.id.to_string(),
            &self.issuer,
            client.as_str(),
            &session.to_string(),
            &account.email,
            &account.username,
            ttl.whole_seconds(),
        )
        .context("sign an access token")?)
    }

    fn id_token(
        &self,
        account: &SignInAccount,
        client: &ClientId,
        nonce: Option<&str>,
        ttl: Duration,
    ) -> Result<String, AuthError> {
        Ok(issue_id_token(
            &self.keypair,
            &self.issuer,
            &account.id.to_string(),
            client.as_str(),
            &account.email,
            &account.username,
            nonce.map(ToOwned::to_owned),
            ttl.whole_seconds(),
        )
        .context("sign an ID token")?)
    }
}

/// The random part appended to a chosen name, uniform over the handle alphabet.
pub struct RandomSuffixes;

impl HandleSuffixes for RandomSuffixes {
    fn fresh(&self) -> HandleSuffix {
        let alphabet = HandleSuffix::ALPHABET.as_bytes();
        let suffix: String = (0..HandleSuffix::LEN)
            .map(|_| char::from(alphabet[OsRng.gen_range(0..alphabet.len())]))
            .collect();
        HandleSuffix::parse(&suffix).expect("drawn from the handle alphabet")
    }
}

/// Argon2id; the parameters are read from each stored hash.
pub struct Argon2Hasher {
    decoy: PasswordHash,
}

/// RFC 6238 through `totp-rs`: SHA-1, six digits, 30 s steps, one step of drift either way.
pub struct TotpAuthenticator;

fn totp(secret: &TotpSecret, issuer: &str, account: &str) -> Result<TOTP, AuthError> {
    let issuer = (!issuer.is_empty()).then(|| issuer.to_owned());
    Ok(TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret.as_bytes().to_vec(),
        issuer,
        account.to_owned(),
    )
    .map_err(|e| anyhow::anyhow!("build a TOTP: {e}"))?)
}

impl Authenticator for TotpAuthenticator {
    fn new_secret(&self) -> TotpSecret {
        let mut secret = vec![0u8; TotpSecret::LEN];
        OsRng.fill_bytes(&mut secret);
        TotpSecret::parse(secret).expect("20 bytes")
    }

    fn base32(&self, secret: &TotpSecret) -> String {
        base32::encode(
            base32::Alphabet::Rfc4648 { padding: false },
            secret.as_bytes(),
        )
    }

    fn provisioning_url(
        &self,
        secret: &TotpSecret,
        issuer: &str,
        account: &str,
    ) -> Result<String, AuthError> {
        // The Key URI format keeps `:` to split the label into issuer and account: neither may
        // hold one, as `localhost:8080` in an instance's name does.
        let fit = |part: &str| part.replace(':', " ");
        Ok(totp(secret, &fit(issuer), &fit(account))?.get_url())
    }

    fn matching_step(&self, secret: &TotpSecret, code: &str, now: OffsetDateTime) -> Option<i64> {
        // Pasted codes often carry spaces.
        let code: String = code.chars().filter(|c| !c.is_whitespace()).collect();
        if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        let totp = totp(secret, "", "").ok()?;
        let step = now.unix_timestamp().div_euclid(30);
        (step - 1..=step + 1)
            .find(|step| u64::try_from(step * 30).is_ok_and(|at| same(&totp.generate(at), &code)))
    }
}

/// In constant time, so the comparison tells nothing of how much of a code was right.
fn same(expected: &str, given: &str) -> bool {
    expected.len() == given.len()
        && expected
            .bytes()
            .zip(given.bytes())
            .fold(0, |diff, (a, b)| diff | (a ^ b))
            == 0
}

/// Argon2id with 64 MiB, three passes and four lanes.
fn argon2id() -> Argon2<'static> {
    let params = argon2::Params::new(65536, 3, 4, None).expect("valid Argon2 parameters");
    Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
}

impl Argon2Hasher {
    /// Hashes a random password once, with the parameters registration uses.
    pub fn new() -> Self {
        let mut password = [0u8; 32];
        OsRng.fill_bytes(&mut password);
        let decoy = argon2id()
            .hash_password(&password, &SaltString::generate(&mut OsRng))
            .expect("hash the decoy password")
            .to_string();
        Self {
            decoy: PasswordHash::new(decoy),
        }
    }
}

impl Default for Argon2Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl PasswordHasher for Argon2Hasher {
    fn hash(&self, password: &str) -> Result<PasswordHash, AuthError> {
        let hash = argon2id()
            .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))
            .map_err(|e| anyhow::anyhow!("hash a password: {e}"))?
            .to_string();
        Ok(PasswordHash::new(hash))
    }

    fn verify(&self, password: &str, hash: &PasswordHash) -> bool {
        argon2::PasswordHash::new(hash.as_str()).is_ok_and(|parsed| {
            Argon2::default()
                .verify_password(password.as_bytes(), &parsed)
                .is_ok()
        })
    }

    fn decoy(&self) -> &PasswordHash {
        &self.decoy
    }
}

#[cfg(test)]
mod tests;
