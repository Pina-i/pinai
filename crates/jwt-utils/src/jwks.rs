use base64ct::{Base64UrlUnpadded, Encoding};
use serde::Serialize;

use crate::EdKeyPair;

/// A single JSON Web Key in OKP format (RFC 8037) for Ed25519.
#[derive(Debug, Serialize)]
pub struct Jwk {
    pub kty: &'static str, // "OKP"
    pub crv: &'static str, // "Ed25519"
    pub kid: String,
    #[serde(rename = "use")]
    pub use_: &'static str, // "sig"
    pub alg: &'static str,  // "EdDSA"
    pub x: String,           // base64url(public_key_bytes), no padding
}

/// A JSON Web Key Set.
#[derive(Debug, Serialize)]
pub struct JwkSet {
    pub keys: Vec<Jwk>,
}

impl JwkSet {
    /// Build a JWKS from one or more EdKeyPair values.
    /// Pass multiple keypairs when rotating keys — keep the old key in the
    /// set for at least the maximum JWT lifetime before removing it.
    pub fn from_keypairs(pairs: &[&EdKeyPair]) -> Self {
        let keys = pairs
            .iter()
            .map(|kp| Jwk {
                kty: "OKP",
                crv: "Ed25519",
                kid: kp.kid.clone(),
                use_: "sig",
                alg: "EdDSA",
                // base64url without padding — RFC 8037 §2
                x: Base64UrlUnpadded::encode_string(&kp.verifying_key_bytes),
            })
            .collect();
        Self { keys }
    }
}
