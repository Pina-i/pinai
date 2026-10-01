use std::sync::Arc;

use anyhow::Context;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use domain::DeviceId;
use domain::e2ee::{
    Claim, ClaimedKeyPackage, KeyPackageBytes, RemoteClaimError, RemoteKeyPackages,
};
use domain::identity::ActorUri;
use federation_transport::{Signer, TransportError, UrlPolicy, send_signed_post};
use jwt_utils::EdKeyPair;
use reqwest::StatusCode;
use serde::Deserialize;
use time::OffsetDateTime;

/// Claims from the instance hosting the account, signed as the local account asking — a
/// browser cannot sign as its instance.
pub struct SignedRemoteKeyPackages {
    keypair: Arc<EdKeyPair>,
    policy: UrlPolicy,
}

impl SignedRemoteKeyPackages {
    pub fn new(keypair: Arc<EdKeyPair>, policy: UrlPolicy) -> Self {
        Self { keypair, policy }
    }
}

#[derive(Deserialize)]
struct ClaimedDto {
    key_package: String,
    device_id: uuid::Uuid,
    #[serde(with = "time::serde::rfc3339")]
    expires_at: OffsetDateTime,
    remaining_count: usize,
    needs_refill: bool,
}

#[async_trait::async_trait]
impl RemoteKeyPackages for SignedRemoteKeyPackages {
    async fn claim(
        &self,
        sender: &ActorUri,
        target: &ActorUri,
        device: Option<DeviceId>,
    ) -> Result<Claim, RemoteClaimError> {
        // Actor URIs are canonical `{scheme}://{domain}/users/{name}`: no WebFinger needed.
        let endpoint = format!(
            "{}://{}/api/keys/packages/claim",
            target.scheme(),
            target.domain()
        );
        let body = serde_json::json!({
            "actor_uri": target.as_str(),
            "device_id": device.map(|d| d.as_uuid()),
        });
        let key_id = format!("{sender}#main-key");
        let signer = Signer {
            key_id: &key_id,
            signing_key: &self.keypair.signing_key,
        };
        let response = send_signed_post(
            &signer,
            &endpoint,
            body.to_string().as_bytes(),
            "application/json",
            self.policy,
        )
        .await
        .map_err(|e| match e {
            TransportError::BadRequest(reason) | TransportError::Denied(reason) => {
                RemoteClaimError::NotAllowed(reason)
            }
            other => RemoteClaimError::Unavailable(
                anyhow::Error::from(other).context("claim a KeyPackage from a peer"),
            ),
        })?;
        // The peer's refusals mean the same as ours; its description is its own business.
        match response.status() {
            status if status.is_success() => {}
            StatusCode::NOT_FOUND => return Err(RemoteClaimError::UserNotFound),
            StatusCode::CONFLICT => return Err(RemoteClaimError::NoKeyPackage),
            StatusCode::TOO_MANY_REQUESTS => return Err(RemoteClaimError::Busy),
            StatusCode::FORBIDDEN => return Err(RemoteClaimError::Unreachable),
            status => {
                let text = response.text().await.unwrap_or_default();
                return Err(RemoteClaimError::Unavailable(anyhow::anyhow!(
                    "the peer answered a claim with {status}: {text}"
                )));
            }
        }
        let claimed: ClaimedDto = response
            .json()
            .await
            .context("read a peer's KeyPackage claim")?;
        let bytes = B64
            .decode(&claimed.key_package)
            .context("a peer's KeyPackage is not base64")?;
        Ok(Claim {
            package: ClaimedKeyPackage {
                device: claimed.device_id.into(),
                bytes: KeyPackageBytes::parse(bytes).context("a peer's KeyPackage")?,
                expires_at: claimed.expires_at,
            },
            remaining: claimed.remaining_count,
            needs_refill: claimed.needs_refill,
        })
    }
}

#[cfg(test)]
mod tests;
