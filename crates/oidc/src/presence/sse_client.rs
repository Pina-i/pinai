//! Outbound SSE client.
//!
//! Connects to a remote IdP's `GET /api/presence/stream?actors[]=...` endpoint,
//! signs the request with HTTP Signatures, parses incoming `event: presence`
//! and `event: typing` frames, and republishes them onto the local Redis
//! pub-sub channels so the local presence subscriber + WS fanout pick them up
//! transparently.
//!
//! One task per remote domain. Lifetime managed by `RemotePresenceRegistry`.

use std::sync::Arc;
use std::time::Duration;

use idp_broker::EventBroker;
use idp_config::Config;
use jwt_utils::EdKeyPair;
use reqwest::header::{HeaderMap, HeaderValue};
use tracing::{info, warn};

use super::types::{PresenceEvent, TypingEvent};

const RECONNECT_INITIAL: Duration = Duration::from_secs(2);
const RECONNECT_MAX: Duration = Duration::from_secs(30);

/// Long-running task that maintains one outbound SSE connection to `domain`,
/// filtering on the supplied `actor_uris`. Reconnects on failure with
/// exponential backoff up to `RECONNECT_MAX`.
///
/// Stops when the task handle is aborted (via `RemotePresenceRegistry::unwatch`).
pub async fn run_sse_connection(
    domain: String,
    actor_uris: Vec<String>,
    keypair: Arc<EdKeyPair>,
    config: Arc<Config>,
    broker: Arc<dyn EventBroker>,
) {
    let mut backoff = RECONNECT_INITIAL;

    loop {
        match connect_and_stream(&domain, &actor_uris, &keypair, &config, &broker).await {
            Ok(()) => {
                // Server closed cleanly — reconnect quickly.
                backoff = RECONNECT_INITIAL;
            }
            Err(e) => {
                warn!(%domain, "SSE connection ended: {e}; reconnecting in {:?}", backoff);
            }
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(RECONNECT_MAX);
    }
}

async fn connect_and_stream(
    domain: &str,
    actor_uris: &[String],
    keypair: &EdKeyPair,
    config: &Config,
    broker: &Arc<dyn EventBroker>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if actor_uris.is_empty() {
        return Err("no actor_uris to subscribe to".into());
    }

    let scheme = if domain.starts_with("localhost") || domain.starts_with("127.") {
        "http"
    } else {
        "https"
    };

    // Build URL with actors[] query params.
    let mut url = reqwest::Url::parse(&format!("{scheme}://{domain}/api/presence/stream"))?;
    {
        let mut q = url.query_pairs_mut();
        for a in actor_uris {
            q.append_pair("actors[]", a);
        }
    }
    let path_and_query = match url.query() {
        Some(q) => format!("{}?{}", url.path(), q),
        None => url.path().to_string(),
    };

    let date = http_signatures::http_date_now();
    let key_id = format!("{}/actor#main-key", config.issuer());
    let signature = http_signatures::sign_request(http_signatures::SignParams {
        method: "get",
        path: &path_and_query,
        host: domain,
        date: &date,
        digest: None,
        key_id: &key_id,
        signing_key: &keypair.signing_key,
    })?;

    let mut headers = HeaderMap::new();
    headers.insert("Host", HeaderValue::from_str(domain)?);
    headers.insert("Date", HeaderValue::from_str(&date)?);
    headers.insert("Signature", HeaderValue::from_str(&signature)?);
    headers.insert("Accept", HeaderValue::from_static("text/event-stream"));

    // No `timeout`/`read_timeout` — SSE responses are open-ended; reqwest's
    // defaults (no per-request or per-read timeout) are exactly what we want.
    // A short connect timeout is fine: if the upstream is down we want the
    // backoff loop to retry rather than hang.
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .build()?;

    let mut response = client.get(url).headers(headers).send().await?;
    if !response.status().is_success() {
        return Err(format!("SSE upstream returned HTTP {}", response.status()).into());
    }

    info!(%domain, actor_count = actor_uris.len(), "SSE connection established");

    // Minimal SSE parser: accumulates bytes, splits on "\n\n", parses each frame.
    let mut buf = Vec::<u8>::new();
    while let Some(chunk) = response.chunk().await? {
        buf.extend_from_slice(&chunk);

        loop {
            // Look for end-of-frame marker (handle \n\n and \r\n\r\n).
            let nn = buf.windows(2).position(|w| w == b"\n\n");
            let rnrn = buf.windows(4).position(|w| w == b"\r\n\r\n");
            let (idx, sep_len) = match (nn, rnrn) {
                (Some(a), Some(b)) if a <= b => (a, 2),
                (Some(a), None) => (a, 2),
                (_, Some(b)) => (b, 4),
                (None, None) => break,
            };
            let frame_bytes = buf.drain(..idx + sep_len).collect::<Vec<_>>();
            let frame = String::from_utf8_lossy(&frame_bytes[..idx]).into_owned();
            handle_sse_frame(&frame, config, broker).await;
        }
    }

    Ok(())
}

/// Parse one SSE frame and dispatch to local Redis if it's a presence/typing event.
async fn handle_sse_frame(frame: &str, config: &Config, broker: &Arc<dyn EventBroker>) {
    let mut event_name: Option<&str> = None;
    let mut data_lines: Vec<&str> = Vec::new();

    for line in frame.split('\n') {
        let line = line.trim_end_matches('\r');
        if line.is_empty() || line.starts_with(':') {
            continue;
        }
        if let Some(v) = line.strip_prefix("event:") {
            event_name = Some(v.trim());
        } else if let Some(v) = line.strip_prefix("data:") {
            data_lines.push(v.trim_start());
        }
        // id: lines are ignored — we don't currently track Last-Event-ID.
    }

    let event = match event_name {
        Some(e) => e,
        None => return,
    };
    if data_lines.is_empty() {
        return;
    }
    let data = data_lines.join("\n");

    match event {
        "presence" => {
            // Validate shape, then republish on the local presence channel so
            // the local subscriber updates the PresenceStore + fans out to WS.
            if let Ok(parsed) = serde_json::from_str::<PresenceEvent>(&data) {
                let channel = format!("presence:{}", config.domain);
                if let Err(e) = broker.publish_presence(&channel, &data).await {
                    warn!("SSE: failed to republish presence event: {e}");
                }
                tracing::debug!(actor = %parsed.actor_uri, "SSE: republished presence event");
            } else {
                warn!("SSE: invalid presence payload: {data}");
            }
        }
        "typing" => {
            if let Ok(parsed) = serde_json::from_str::<TypingEvent>(&data) {
                let channel = format!("typing:{}", parsed.conversation_id);
                if let Err(e) = broker.publish_presence(&channel, &data).await {
                    warn!("SSE: failed to republish typing event: {e}");
                }
            } else {
                warn!("SSE: invalid typing payload: {data}");
            }
        }
        _ => {
            // Unknown event type (e.g. keep-alive) — ignore.
        }
    }
}
