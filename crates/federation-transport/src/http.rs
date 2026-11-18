//! Shared HTTP client for peer requests.
//!
//! Peer URLs come from an attacker-controlled `keyId`, so every outbound fetch
//! is bounded in time, redirects and body size, and screened against private
//! address space before it is made.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::OnceLock;
use std::time::Duration;

use futures_util::StreamExt;

use crate::error::TransportError;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_REDIRECTS: usize = 2;
const MAX_BODY_BYTES: usize = 256 * 1024;
const MAX_REFUSAL_BYTES: usize = 1024;
const REFUSAL_EXCERPT_CHARS: usize = 200;
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

/// One client for the whole process, so the connection pool is actually reused. It follows no
/// redirect itself, as it would not screen the target: [`get_json_screened`] follows them, and a
/// signed POST follows none.
pub fn client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(TOTAL_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent("pinai-federation/0.1")
            .build()
            .expect("failed to build the shared HTTP client")
    })
}

fn is_private(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_documentation()
                || v4.is_multicast()
                // 0.0.0.0/8, which Linux connects to as this host
                || a == 0
                // 100.64.0.0/10 carrier-grade NAT
                || (a == 100 && (64..128).contains(&b))
                // 192.0.0.0/24 IETF protocol assignments
                || (a, b, c) == (192, 0, 0)
                // 198.18.0.0/15 benchmarking
                || (a == 198 && (b & 0xfe) == 18)
                // 240.0.0.0/4 reserved, the broadcast address included
                || a >= 240
        }
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // fc00::/7 unique local
                || (segments[0] & 0xfe00) == 0xfc00
                // fe80::/10 link local
                || (segments[0] & 0xffc0) == 0xfe80
                // IPv4-mapped and -compatible addresses are held to the v4 rules
                || v6.to_ipv4().is_some_and(|v4| is_private(&IpAddr::V4(v4)))
                // NAT64 64:ff9b::/96 reaches the IPv4 address it ends with
                || (segments[..6] == [0x64, 0xff9b, 0, 0, 0, 0]
                    && is_private(&IpAddr::V4(Ipv4Addr::from(
                        (u32::from(segments[6]) << 16) | u32::from(segments[7]),
                    ))))
                // 64:ff9b:1::/48, local-use NAT64, maps however its network chose
                || segments[..3] == [0x64, 0xff9b, 1]
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

    let port = url.port_or_known_default().unwrap_or(443);
    let addresses: Vec<IpAddr> = match url.host() {
        Some(url::Host::Ipv4(ip)) => vec![IpAddr::V4(ip)],
        Some(url::Host::Ipv6(ip)) => vec![IpAddr::V6(ip)],
        Some(url::Host::Domain(host)) => tokio::net::lookup_host((host, port))
            .await
            .map_err(|e| TransportError::Upstream(format!("DNS lookup failed for {host}: {e}")))?
            .map(|address| address.ip())
            .collect(),
        None => return Err(TransportError::BadRequest("peer URL has no host".into())),
    };

    if addresses.is_empty() {
        return Err(TransportError::Upstream(format!(
            "{url} did not resolve to any address"
        )));
    }
    if let Some(private) = addresses.iter().find(|ip| is_private(ip)) {
        return Err(TransportError::Denied(format!(
            "peer URL resolves into private address space ({private})"
        )));
    }

    Ok(url)
}

/// GET a screened URL and decode JSON, refusing a body over [`MAX_BODY_BYTES`]. At most
/// [`MAX_REDIRECTS`] redirects are followed, each on the origin asked and screened before it is
/// asked; the screens, every request and the body share one [`TOTAL_TIMEOUT`].
pub async fn get_json_screened(
    raw_url: &str,
    accept: &str,
    policy: UrlPolicy,
) -> Result<serde_json::Value, TransportError> {
    get_json_within(raw_url, accept, policy, TOTAL_TIMEOUT).await
}

async fn get_json_within(
    raw_url: &str,
    accept: &str,
    policy: UrlPolicy,
    deadline: Duration,
) -> Result<serde_json::Value, TransportError> {
    tokio::time::timeout(deadline, fetch_json(raw_url, accept, policy))
        .await
        .map_err(|_| TransportError::Upstream(format!("peer took more than {deadline:?}")))?
}

async fn fetch_json(
    raw_url: &str,
    accept: &str,
    policy: UrlPolicy,
) -> Result<serde_json::Value, TransportError> {
    let mut url = screen_url(raw_url, policy).await?;
    let mut redirects = 0;
    let resp = loop {
        let resp = client()
            .get(url.clone())
            .header("Accept", accept)
            .send()
            .await
            .map_err(|e| TransportError::Upstream(format!("fetch failed: {e}")))?;
        if !is_redirect(resp.status()) {
            break resp;
        }
        if redirects == MAX_REDIRECTS {
            return Err(TransportError::Upstream(format!(
                "peer redirected more than {MAX_REDIRECTS} times"
            )));
        }
        redirects += 1;
        let location = resp.headers().get(reqwest::header::LOCATION);
        url = redirect_target(&url, location, policy).await?;
    };

    let status = resp.status();
    if status == reqwest::StatusCode::NOT_FOUND || status == reqwest::StatusCode::GONE {
        return Err(TransportError::NotFound(format!("peer returned {status}")));
    }
    if !status.is_success() {
        return Err(TransportError::Upstream(format!("peer returned {status}")));
    }

    let buf = read_capped(resp).await?;
    serde_json::from_slice(&buf)
        .map_err(|e| TransportError::Upstream(format!("peer returned invalid JSON: {e}")))
}

/// The statuses a GET is redirected by.
fn is_redirect(status: reqwest::StatusCode) -> bool {
    matches!(status.as_u16(), 301 | 302 | 303 | 307 | 308)
}

/// Where a redirect from `from` leads: on the same origin, so what answers a URL is always its
/// own origin's, and screened as the first URL was. A refusal is the peer's doing: `Upstream`.
async fn redirect_target(
    from: &url::Url,
    location: Option<&reqwest::header::HeaderValue>,
    policy: UrlPolicy,
) -> Result<url::Url, TransportError> {
    let location = location
        .ok_or_else(|| TransportError::Upstream("peer redirected without a Location".into()))?
        .to_str()
        .map_err(|_| TransportError::Upstream("peer redirected to a non-ASCII Location".into()))?;
    let target = from
        .join(location)
        .map_err(|e| TransportError::Upstream(format!("peer redirected to no URL: {e}")))?;
    if target.origin() != from.origin() {
        return Err(TransportError::Upstream(format!(
            "peer redirected off its origin, to {target}"
        )));
    }
    screen_url(target.as_str(), policy)
        .await
        .map_err(|e| TransportError::Upstream(format!("peer redirect refused: {e}")))
}

/// A peer's whole answer, refusing a body over [`MAX_BODY_BYTES`].
///
/// Streams rather than using `Response::bytes`, which would buffer a body of any
/// size a hostile peer cared to send.
pub async fn read_capped(resp: reqwest::Response) -> Result<Vec<u8>, TransportError> {
    if let Some(len) = resp.content_length() {
        if len as usize > MAX_BODY_BYTES {
            return Err(TransportError::Upstream(format!(
                "peer body of {len} bytes exceeds the {MAX_BODY_BYTES} byte cap"
            )));
        }
    }

    // Content-Length is advisory: a chunked response can omit it and stream
    // forever, so the cap is enforced as the bytes arrive.
    match read_up_to(resp, MAX_BODY_BYTES).await? {
        (buf, true) => Ok(buf),
        (_, false) => Err(TransportError::Upstream(format!(
            "peer body exceeds the {MAX_BODY_BYTES} byte cap"
        ))),
    }
}

/// What a peer's refusal says, as one short line fit for an error or a log: only its first
/// [`MAX_REFUSAL_BYTES`] are read, and [`REFUSAL_EXCERPT_CHARS`] of them kept.
pub async fn refusal_excerpt(resp: reqwest::Response) -> String {
    let (read, whole) = read_up_to(resp, MAX_REFUSAL_BYTES)
        .await
        .unwrap_or_default();
    let text = String::from_utf8_lossy(&read);
    let line = text
        .split(|c: char| c.is_whitespace() || c.is_control())
        .filter(|word| !word.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    let mut excerpt: String = line.chars().take(REFUSAL_EXCERPT_CHARS).collect();
    if !whole || excerpt.len() < line.len() {
        excerpt.push('…');
    }
    excerpt
}

/// A peer's body up to `cap` bytes, and whether that is all of it; nothing past `cap` is read.
async fn read_up_to(
    resp: reqwest::Response,
    cap: usize,
) -> Result<(Vec<u8>, bool), TransportError> {
    let mut buf: Vec<u8> = Vec::new();
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| TransportError::Upstream(format!("read failed: {e}")))?;
        if buf.len() + chunk.len() > cap {
            let room = cap - buf.len();
            buf.extend_from_slice(&chunk[..room]);
            return Ok((buf, false));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok((buf, true))
}

#[cfg(test)]
mod tests;
