//! Device attestations, signed with the instance's key — identity-provider/specs/05-e2ee.md § 7.2.

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use domain::DeviceId;
use domain::e2ee::{DeviceAttester, DeviceRootKey, SignedAttestation};
use domain::identity::ActorUri;
use ed25519_dalek::Signer;
use jwt_utils::EdKeyPair;
use time::OffsetDateTime;
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
        expires_at: OffsetDateTime,
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

/// The `IDP-ATTEST-v1` tag keeps the signature from verifying as any other use of the key; a
/// change to these fields needs a new tag.
fn canonical_bytes(
    actor: &str,
    device: DeviceId,
    key: &[u8],
    expires_at: OffsetDateTime,
    kid: &str,
) -> Vec<u8> {
    let expires_at = expires_at
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
