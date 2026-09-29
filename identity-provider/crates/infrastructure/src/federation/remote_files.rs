use std::sync::Arc;

use anyhow::Context;
use domain::messaging::{ByteStream, ObjectStoreError, RemoteFiles};
use federation_transport::{Signer, UrlPolicy, signed_get};
use futures_util::TryStreamExt;
use jwt_utils::EdKeyPair;

/// Fetches an attachment another instance hosts, signed as this instance's actor, through the
/// peer URL screening.
pub struct SignedRemoteFiles {
    keypair: Arc<EdKeyPair>,
    issuer: String,
    policy: UrlPolicy,
}

impl SignedRemoteFiles {
    pub fn new(keypair: Arc<EdKeyPair>, issuer: String, policy: UrlPolicy) -> Self {
        Self {
            keypair,
            issuer,
            policy,
        }
    }
}

#[async_trait::async_trait]
impl RemoteFiles for SignedRemoteFiles {
    async fn fetch(&self, url: &str) -> Result<ByteStream, ObjectStoreError> {
        let key_id = format!("{}/actor#main-key", self.issuer);
        let signer = Signer {
            key_id: &key_id,
            signing_key: &self.keypair.signing_key,
        };
        let response = signed_get(&signer, url, self.policy)
            .await
            .context("fetch a remote attachment")?;
        Ok(ByteStream {
            length: None,
            chunks: Box::pin(response.bytes_stream().map_err(std::io::Error::other)),
        })
    }
}

#[cfg(test)]
mod tests;
