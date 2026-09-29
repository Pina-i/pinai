//! Shared HTTP client for peer requests.
//!
//! Peer URLs come from an attacker-controlled `keyId`, so every outbound fetch
//! is bounded in time, redirects and body size, and screened against private
//! address space before it is made.

use std::net::IpAddr;
use std::sync::OnceLock;
use std::time::Duration;

use futures_util::StreamExt;

use crate::error::TransportError;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_REDIRECTS: usize = 2;
const MAX_BODY_BYTES: usize = 256 * 1024;
const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// What a peer URL is allowed to be.
#[derive(Clone, Copy, Debug)]
pub struct UrlPolicy {
    /// Reject non-HTTPS peers. Off for local dev over `http://localhost`.
    pub require_https: bool,
    /// Permit loopback and private ranges. On for the alice/bob dev instances,
    /// which federate over `localhost`.
    pub allow_private_networks: bool,
}

impl UrlPolicy {
    /// Derive the policy from the local issuer: an https deployment is treated
    /// as production, a plain-http one as local dev.
    pub fn from_issuer(issuer: &str) -> Self {
        let https = issuer.starts_with("https");
        Self {
            require_https: https,
            allow_private_networks: !https,
        }
    }
}

/// For downloads: never follows a redirect — the target was screened, a hop would not be — and has
/// no total timeout, as a file takes what it takes; a stalled read still times out.
pub fn download_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .read_timeout(READ_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent("pinai-federation/0.1")
            .build()
            .expect("failed to build the download HTTP client")
    })
}

/// One client for the whole process, so the connection pool is actually reused.
pub fn client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(TOTAL_TIMEOUT)
            .redirect(reqwest::redirect::Policy::limited(MAX_REDIRECTS))
            .user_agent("pinai-federation/0.1")
            .build()
            .expect("failed to build the shared HTTP client")
    })
}

fn is_private(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                // 100.64.0.0/10 carrier-grade NAT
                || (v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1]))
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // fc00::/7 unique local
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                // fe80::/10 link local
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                // mapped IPv4 still has to pass the v4 rules
                || v6.to_ipv4_mapped().map(|m| is_private(&IpAddr::V4(m))) == Some(true)
        }
    }
}

/// Screen a peer URL before fetching it.
///
/// Resolution here and connection in reqwest are separate lookups, so a
/// hostile DNS server can still answer differently for each (a rebinding
/// TOCTOU). Closing that needs a custom connector pinned to the screened
/// address; this blocks the direct attempt, not that race.
pub async fn screen_url(raw: &str, policy: UrlPolicy) -> Result<url::Url, TransportError> {
    let url: url::Url = raw
        .parse()
        .map_err(|e| TransportError::BadRequest(format!("invalid peer URL: {e}")))?;

    match url.scheme() {
        "https" => {}
        "http" if !policy.require_https => {}
        other => {
            return Err(TransportError::Denied(format!(
                "peer URL scheme {other:?} is not allowed"
            )))
        }
    }

    if policy.allow_private_networks {
        return Ok(url);
    }

    let host = url
        .host_str()
        .ok_or_else(|| TransportError::BadRequest("peer URL has no host".into()))?;
    let port = url.port_or_known_default().unwrap_or(443);

    let resolved = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| TransportError::Upstream(format!("DNS lookup failed for {host}: {e}")))?;

    let mut any = false;
    for addr in resolved {
        any = true;
        if is_private(&addr.ip()) {
            return Err(TransportError::Denied(format!(
                "peer URL resolves into private address space ({})",
                addr.ip()
            )));
        }
    }
    if !any {
        return Err(TransportError::Upstream(format!(
            "{host} did not resolve to any address"
        )));
    }

    Ok(url)
}

/// GET a screened URL and decode JSON, refusing a body over [`MAX_BODY_BYTES`].
pub async fn get_json_screened(
    raw_url: &str,
    accept: &str,
    policy: UrlPolicy,
) -> Result<serde_json::Value, TransportError> {
    let url = screen_url(raw_url, policy).await?;

    let resp = client()
        .get(url)
        .header("Accept", accept)
        .send()
        .await
        .map_err(|e| TransportError::Upstream(format!("fetch failed: {e}")))?;

    if !resp.status().is_success() {
        return Err(TransportError::Upstream(format!(
            "peer returned {}",
            resp.status()
        )));
    }

    let buf = read_capped(resp).await?;
    serde_json::from_slice(&buf)
        .map_err(|e| TransportError::Upstream(format!("peer returned invalid JSON: {e}")))
}

/// A peer's whole answer, refusing a body over [`MAX_BODY_BYTES`].
///
/// Streams rather than using `Response::bytes`, which would buffer a body of any
/// size a hostile peer cared to send.
pub async fn read_capped(resp: reqwest::Response) -> Result<Vec<u8>, TransportError> {
    if let Some(len) = resp.content_length() {
        if len as usize > MAX_BODY_BYTES {
            return Err(TransportError::Denied(format!(
                "peer body of {len} bytes exceeds the {MAX_BODY_BYTES} byte cap"
            )));
        }
    }

    // Content-Length is advisory: a chunked response can omit it and stream
    // forever, so the cap is enforced as the bytes arrive.
    let mut buf: Vec<u8> = Vec::new();
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| TransportError::Upstream(format!("read failed: {e}")))?;
        if buf.len() + chunk.len() > MAX_BODY_BYTES {
            return Err(TransportError::Denied(format!(
                "peer body exceeds the {MAX_BODY_BYTES} byte cap"
            )));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

#[cfg(test)]
mod tests;
