use std::time::Duration;

use ed25519_dalek::SigningKey;
use http_signatures::{http_date_now, sha256_digest, sign_request, SignParams};
use tracing::debug;

use crate::error::TransportError;
use crate::http::{
    client, download_client, refusal_excerpt, request_failed, screen_url, UrlPolicy, TOTAL_TIMEOUT,
};

/// The identity a signed request is made under.
pub struct Signer<'a> {
    /// ActivityPub key ID, e.g. `https://idp.alice.com/users/alice#main-key`.
    pub key_id: &'a str,
    pub signing_key: &'a SigningKey,
}

/// POST a signed body to a peer and return the response; a non-2xx answer is an error carrying
/// an excerpt of the peer's refusal.
///
/// Callers choose the content type (`application/activity+json` for AP
/// delivery, `application/json` for direct peer APIs) and decide what to do
/// with the body, read through [`crate::http::read_capped`].
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
        let excerpt = refusal_excerpt(resp).await;
        return Err(TransportError::Upstream(format!(
            "peer returned {status}: {excerpt}"
        )));
    }
    Ok(resp)
}

/// [`signed_post`], answering whatever status the peer chose — for callers that tell a
/// peer's refusals apart. The lookup, the request and the answer's body share one
/// [`TOTAL_TIMEOUT`].
pub async fn send_signed_post(
    signer: &Signer<'_>,
    target_url: &str,
    body: &[u8],
    content_type: &str,
    policy: UrlPolicy,
) -> Result<reqwest::Response, TransportError> {
    send_signed_post_within(
        signer,
        target_url,
        body,
        content_type,
        policy,
        TOTAL_TIMEOUT,
    )
    .await
}

async fn send_signed_post_within(
    signer: &Signer<'_>,
    target_url: &str,
    body: &[u8],
    content_type: &str,
    policy: UrlPolicy,
    deadline: Duration,
) -> Result<reqwest::Response, TransportError> {
    let mut request = signed_post_request(signer, target_url, body, content_type, policy)?;
    // A request's own timeout runs on through the body its caller reads.
    *request.timeout_mut() = Some(deadline);

    debug!(%target_url, "sending signed POST");

    client(policy)
        .execute(request)
        .await
        .map_err(|e| post_failed(e, deadline))
}

/// Why a signed POST got no answer: its deadline, or what the client met — a connect timeout,
/// the name's lookup included, told apart from the deadline.
fn post_failed(error: reqwest::Error, deadline: Duration) -> TransportError {
    if error.is_timeout() && !error.is_connect() {
        TransportError::Upstream(format!("peer took more than {deadline:?}"))
    } else {
        request_failed("signed POST failed", error)
    }
}

fn signed_post_request(
    signer: &Signer<'_>,
    target_url: &str,
    body: &[u8],
    content_type: &str,
    policy: UrlPolicy,
) -> Result<reqwest::Request, TransportError> {
    let url = screen_url(target_url, policy)?;
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

    // No `Host` header: the client writes it from the URL, and over HTTP/2 nginx refuses a
    // request that carries one beside `:authority`.
    client(policy)
        .post(target_url)
        .header("Content-Type", content_type)
        .header("Date", &date)
        .header("Digest", &digest)
        .header("Signature", &signature)
        .body(body.to_vec())
        .build()
        .map_err(|e| TransportError::BadRequest(format!("signed POST: {e}")))
}

/// GET a peer's resource as the signer, to download it: the URL is screened like any peer
/// request, and no redirect is followed, as its target would not be.
pub async fn signed_get(
    signer: &Signer<'_>,
    target_url: &str,
    policy: UrlPolicy,
) -> Result<reqwest::Response, TransportError> {
    let request = signed_get_request(signer, target_url, policy)?;

    debug!(%target_url, "sending signed GET");
    let resp = download_client(policy)
        .execute(request)
        .await
        .map_err(|e| request_failed("signed GET failed", e))?;
    if !resp.status().is_success() {
        return Err(TransportError::Upstream(format!(
            "peer returned {}",
            resp.status()
        )));
    }
    Ok(resp)
}

fn signed_get_request(
    signer: &Signer<'_>,
    target_url: &str,
    policy: UrlPolicy,
) -> Result<reqwest::Request, TransportError> {
    let url = screen_url(target_url, policy)?;
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

    // No `Host` header, as for a POST.
    download_client(policy)
        .get(url)
        .header("Date", &date)
        .header("Signature", &signature)
        .build()
        .map_err(|e| TransportError::BadRequest(format!("signed GET: {e}")))
}

#[cfg(test)]
mod tests;
