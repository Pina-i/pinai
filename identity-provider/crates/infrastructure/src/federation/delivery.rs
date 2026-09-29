use std::sync::Arc;

use domain::identity::ActorUri;
use federation_transport::{Signer, TransportError, UrlPolicy, signed_post};
use jwt_utils::EdKeyPair;
use serde_json::Value;

/// Signs an activity with its sender's key and posts it to a peer's inbox.
#[derive(Clone)]
pub(crate) struct SignedDelivery {
    keypair: Arc<EdKeyPair>,
    policy: UrlPolicy,
}

impl SignedDelivery {
    pub(crate) fn new(keypair: Arc<EdKeyPair>, policy: UrlPolicy) -> Self {
        Self { keypair, policy }
    }

    pub(crate) async fn post(
        &self,
        from: &ActorUri,
        inbox: &url::Url,
        activity: &Value,
    ) -> Result<(), TransportError> {
        // The peer resolves this key id to the sender's actor document to verify the signature.
        let key_id = format!("{from}#main-key");
        let signer = Signer {
            key_id: &key_id,
            signing_key: &self.keypair.signing_key,
        };
        let body = activity.to_string();
        signed_post(
            &signer,
            inbox.as_str(),
            body.as_bytes(),
            "application/activity+json",
            self.policy,
        )
        .await?;
        Ok(())
    }

    /// Fire-and-forget: the failure is logged here, where it is handled.
    pub(crate) fn post_in_background(&self, from: &ActorUri, inbox: &url::Url, activity: Value) {
        let delivery = self.clone();
        let (from, inbox) = (from.clone(), inbox.clone());
        tokio::spawn(async move {
            if let Err(e) = delivery.post(&from, &inbox, &activity).await {
                tracing::warn!(%inbox, activity_type = %activity["type"], error = %e, "activity delivery failed");
            }
        });
    }
}
