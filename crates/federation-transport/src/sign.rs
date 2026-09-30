use ed25519_dalek::SigningKey;
use http_signatures::{http_date_now, sha256_digest, sign_request, SignParams};
use tracing::debug;

use crate::error::TransportError;
use crate::http::{client, download_client, screen_url, UrlPolicy};

/// The identity a signed request is made under.
pub struct Signer<'a> {
    /// ActivityPub key ID, e.g. `https://idp.alice.com/users/alice#main-key`.
    pub key_id: &'a str,
    pub signing_key: &'a SigningKey,
}

/// POST a signed body to a peer and return the response; a non-2xx answer is an error.
///
/// Callers choose the content type (`application/activity+json` for AP
/// delivery, `application/json` for direct peer APIs) and decide what to do
/// with the body.
pub async fn signed_post(
    signer: &Signer<'_>,
    target_url: &str,
    body: &[u8],
    content_type: &str,
    policy: UrlPolicy,
) -> Result<reqwest::Response, TransportError> {
    let resp = send_signed_post(signer, target_url, body, content_type, policy).await?;
    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(TransportError::Upstream(format!(
            "peer returned {status}: {text}"
        )));
    }
    Ok(resp)
}

/// [`signed_post`], answering whatever status the peer chose — for callers that tell a
/// peer's refusals apart.
pub async fn send_signed_post(
    signer: &Signer<'_>,
    target_url: &str,
    body: &[u8],
    content_type: &str,
    policy: UrlPolicy,
) -> Result<reqwest::Response, TransportError> {
    let url = screen_url(target_url, policy).await?;
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

    client()
        .post(target_url)
        .header("Content-Type", content_type)
        .header("Date", &date)
        .header("Digest", &digest)
        .header("Host", &host_with_port)
        .header("Signature", &signature)
        .body(body.to_vec())
        .send()
        .await
        .map_err(|e| TransportError::Upstream(format!("signed POST failed: {e}")))
}

/// GET a peer's resource as the signer, to download it: the URL is screened like any peer
/// request, and no redirect is followed, as its target would not be.
pub async fn signed_get(
    signer: &Signer<'_>,
    target_url: &str,
    policy: UrlPolicy,
) -> Result<reqwest::Response, TransportError> {
    let url = screen_url(target_url, policy).await?;
    let host = url
        .host_str()
        .ok_or_else(|| TransportError::BadRequest("target URL missing host".into()))?;
    let host_with_port = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    };
    let path_and_query = match url.query() {
        Some(q) => format!("{}?{}", url.path(), q),
        None => url.path().to_string(),
    };
    let date = http_date_now();
    let signature = sign_request(SignParams {
        method: "get",
        path: &path_and_query,
        host: &host_with_port,
        date: &date,
        digest: None,
        key_id: signer.key_id,
        signing_key: signer.signing_key,
    })
    .map_err(|e| TransportError::Upstream(format!("HTTP Signature failed: {e}")))?;

    debug!(%target_url, "sending signed GET");
    let resp = download_client()
        .get(url)
        .header("Date", &date)
        .header("Host", &host_with_port)
        .header("Signature", &signature)
        .send()
        .await
        .map_err(|e| TransportError::Upstream(format!("signed GET failed: {e}")))?;
    if !resp.status().is_success() {
        return Err(TransportError::Upstream(format!(
            "peer returned {}",
            resp.status()
        )));
    }
    Ok(resp)
}

#[cfg(test)]
mod tests;
