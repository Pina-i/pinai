use jsonwebtoken::{decode, Algorithm, Validation};

use crate::{AccessTokenClaims, EdKeyPair, JwtUtilsError};

pub fn validate_access_token(
    token: &str,
    keypair: &EdKeyPair,
    expected_issuer: &str,
    expected_audience: &str,
) -> Result<AccessTokenClaims, JwtUtilsError> {
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_issuer(&[expected_issuer]);
    validation.set_audience(&[expected_audience]);
    validation.leeway = 0;

    let data = decode::<AccessTokenClaims>(token, &keypair.decoding_key, &validation)?;
    Ok(data.claims)
}
