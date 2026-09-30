use std::sync::Arc;

use domain::identity::{ActorUri, SignatureError, SignatureVerifier, SignedRequest};
use federation_transport::{KeyCache, TransportError, verify_body_digest, verify_http_signature};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

/// HTTP Signatures of other instances, checked against their published keys through the
/// process's key cache — specs/06-federation-authentication.md § Inbound.
pub struct HttpSignatureVerifier {
    keys: Arc<KeyCache>,
}

impl HttpSignatureVerifier {
    pub fn new(keys: Arc<KeyCache>) -> Self {
        Self { keys }
    }
}

#[async_trait::async_trait]
impl SignatureVerifier for HttpSignatureVerifier {
    async fn verify(&self, request: &SignedRequest) -> Result<ActorUri, SignatureError> {
        let mut headers = HeaderMap::new();
        for (name, value) in &request.headers {
            if let (Ok(name), Ok(value)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                headers.append(name, value);
            }
        }
        let key_id = verify_http_signature(&self.keys, &headers, &request.method, &request.target)
            .await
            .map_err(refusal)?;
        if let Some(body) = &request.body {
            verify_body_digest(&headers, body).map_err(refusal)?;
        }
        // `https://idp.bob.com/actor#main-key`: the actor is the key id without its fragment.
        key_id
            .split('#')
            .next()
            .and_then(|actor| ActorUri::parse(actor).ok())
            .ok_or_else(|| SignatureError::Malformed("invalid keyId in signature".into()))
    }
}

fn refusal(error: TransportError) -> SignatureError {
    match error {
        TransportError::BadRequest(reason) | TransportError::NotFound(reason) => {
            SignatureError::Malformed(reason)
        }
        TransportError::Denied(reason) => SignatureError::Refused(reason),
        TransportError::Upstream(reason) => {
            SignatureError::Unexpected(anyhow::anyhow!("fetch a signing key: {reason}"))
        }
    }
}

#[cfg(test)]
mod tests;
