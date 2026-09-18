use ed25519_dalek::SigningKey;
use http_signatures::{http_date_now, sha256_digest, sign_request, SignParams};
use tracing::{debug, warn};

use crate::error::TransportError;

/// The identity a signed request is made under.
pub struct Signer<'a> {
    /// ActivityPub key ID, e.g. `https://idp.alice.com/users/alice#main-key`.
    pub key_id: &'a str,
    pub signing_key: &'a SigningKey,
}

/// POST a signed body to a peer and return the response.
///
/// Callers choose the content type (`application/activity+json` for AP
/// delivery, `application/json` for direct peer APIs) and decide what to do
/// with the body.
pub async fn signed_post(
    signer: &Signer<'_>,
    target_url: &str,
    body: &[u8],
    content_type: &str,
) -> Result<reqwest::Response, TransportError> {
    let url: url::Url = target_url
        .parse()
        .map_err(|e| TransportError::BadRequest(format!("invalid target URL: {e}")))?;
    let host = url
        .host_str()
        .ok_or_else(|| TransportError::BadRequest("target URL missing host".into()))?;
    let host_with_port = match url.port() {
        Some(port) => format!("{}:{}", host, port),
        None => host.to_string(),
    };
    let path_and_query = match url.query() {
        Some(q) => format!("{}?{}", url.path(), q),
        None => url.path().to_string(),
    };

    let date = http_date_now();
    let digest = sha256_digest(body);

    let signature = sign_request(SignParams {
        method: "post",
        path: &path_and_query,
        host: &host_with_port,
        date: &date,
        digest: Some(&digest),
        key_id: signer.key_id,
        signing_key: signer.signing_key,
    })
    .map_err(|e| TransportError::Upstream(format!("HTTP Signature failed: {e}")))?;

    debug!(%target_url, "sending signed POST");

    let resp = reqwest::Client::new()
        .post(target_url)
        .header("Content-Type", content_type)
        .header("Date", &date)
        .header("Digest", &digest)
        .header("Host", &host_with_port)
        .header("Signature", &signature)
        .body(body.to_vec())
        .send()
        .await
        .map_err(|e| TransportError::Upstream(format!("signed POST failed: {e}")))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        warn!(%target_url, %status, %text, "peer rejected signed POST");
        return Err(TransportError::Upstream(format!(
            "peer returned {status}: {text}"
        )));
    }

    Ok(resp)
}
