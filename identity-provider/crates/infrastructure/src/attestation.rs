//! Device attestations, signed with the instance's key — identity-provider/specs/e2ee.md § 7.2 —
//! and what devices sign with their root keys.

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use domain::DeviceId;
use domain::e2ee::{
    AttestationExpiry, DeviceAttester, DeviceRootKey, Ed25519PublicKey, Ed25519Signature,
    Ed25519Verifier, SignedAttestation,
};
use domain::identity::ActorUri;
use ed25519_dalek::{Signature, Signer, VerifyingKey};
use jwt_utils::EdKeyPair;
use time::format_description::well_known::Rfc3339;

/// Peers verify these against the instance's JWKS, by `kid`.
pub struct Ed25519DeviceAttester {
    keypair: Arc<EdKeyPair>,
}

impl Ed25519DeviceAttester {
    pub fn new(keypair: Arc<EdKeyPair>) -> Self {
        Self { keypair }
    }
}

impl DeviceAttester for Ed25519DeviceAttester {
    fn attest(
        &self,
        actor: &ActorUri,
        device: DeviceId,
        key: &DeviceRootKey,
        expires_at: AttestationExpiry,
    ) -> SignedAttestation {
        let signed_message = canonical_bytes(
            actor.as_str(),
            device,
            key.as_bytes(),
            expires_at,
            &self.keypair.kid,
        );
        SignedAttestation {
            signature: self
                .keypair
                .signing_key
                .sign(&signed_message)
                .to_bytes()
                .to_vec(),
            kid: self.keypair.kid.clone(),
            signed_message,
        }
    }
}

pub struct StrictEd25519Verifier;

impl Ed25519Verifier for StrictEd25519Verifier {
    fn verifies(
        &self,
        key: &dyn Ed25519PublicKey,
        message: &[u8],
        signature: &Ed25519Signature,
    ) -> bool {
        let (Ok(key), Ok(signature)) = (
            VerifyingKey::from_bytes(key.public_bytes()),
            Signature::from_slice(signature.as_bytes()),
        ) else {
            return false;
        };
        // Strict: a small-order key would accept signatures no private key made.
        key.verify_strict(message, &signature).is_ok()
    }
}

/// The `IDP-ATTEST-v1` tag keeps the signature from verifying as any other use of the key; a
/// change to these fields needs a new tag.
fn canonical_bytes(
    actor: &str,
    device: DeviceId,
    key: &[u8],
    expires_at: AttestationExpiry,
    kid: &str,
) -> Vec<u8> {
    let expires_at = expires_at
        .at()
        .format(&Rfc3339)
        .expect("any OffsetDateTime formats as RFC 3339");
    format!(
        "IDP-ATTEST-v1\n{actor}\n{device}\n{}\n{expires_at}\n{kid}",
        B64.encode(key)
    )
    .into_bytes()
}

#[cfg(test)]
mod tests;
