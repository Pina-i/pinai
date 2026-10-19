//! Clients as their own documents describe them — the OAuth Client ID Metadata Document draft.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{Context, anyhow, bail};
use domain::auth::{AuthError, Client, ClientDocument, ClientId, ClientPolicy, Clients};
use federation_transport::UrlPolicy;
use federation_transport::http::screen_url;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_DOCUMENT_BYTES: usize = 5 * 1024;
const MIN_TTL: Duration = Duration::from_secs(5 * 60);
const MAX_TTL: Duration = Duration::from_secs(24 * 60 * 60);
/// A client whose document can't be had is asked again only after this.
const FAILURE_TTL: Duration = Duration::from_secs(60);
/// Any URL can be offered as a client, so the cache is bounded.
const MAX_ENTRIES: usize = 1024;

/// A screened `GET` to a URL anyone can name: no redirect is followed, since its target was never
/// screened.
fn http() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(FETCH_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("a static client configuration")
    })
}

struct Cached {
    client: Option<Client>,
    until: Instant,
}

pub struct MetadataClients {
    urls: UrlPolicy,
    policy: ClientPolicy,
    /// Described by this instance itself, never fetched: the official desktop app.
    built_in: Vec<Client>,
    cache: Mutex<HashMap<ClientId, Cached>>,
}

impl MetadataClients {
    pub fn new(urls: UrlPolicy, built_in: Vec<Client>) -> Self {
        Self {
            urls,
            policy: ClientPolicy {
                allow_http: !urls.require_https,
            },
            built_in,
            cache: Mutex::new(HashMap::new()),
        }
    }

    async fn find_at(&self, id: &ClientId, now: Instant) -> Option<Client> {
        if let Some(client) = self.built_in.iter().find(|client| client.id == *id) {
            return Some(client.clone());
        }
        if let Some(cached) = self.cache.lock().unwrap().get(id)
            && cached.until > now
        {
            return cached.client.clone();
        }
        let (client, ttl) = match self.fetch(id).await {
            Ok((client, ttl)) => (Some(client), ttl),
            Err(error) => {
                tracing::warn!(client = id.as_str(), error = %format!("{error:#}"), "client document refused");
                (None, FAILURE_TTL)
            }
        };
        self.keep(id, client.clone(), now + ttl, now);
        client
    }

    async fn fetch(&self, id: &ClientId) -> anyhow::Result<(Client, Duration)> {
        let url = screen_url(id.as_str(), self.urls)
            .await
            .map_err(|e| anyhow!("{e}"))?;
        let mut response = http()
            .get(url)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .context("fetch the document")?;
        if !response.status().is_success() {
            bail!("the document answered {}", response.status());
        }
        let ttl = ttl_of(
            response
                .headers()
                .get(reqwest::header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
        );
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.context("read the document")? {
            if body.len() + chunk.len() > MAX_DOCUMENT_BYTES {
                bail!("the document is over {MAX_DOCUMENT_BYTES} bytes");
            }
            body.extend_from_slice(&chunk);
        }
        let document: ClientDocument =
            serde_json::from_slice(&body).context("decode the document")?;
        let client = Client::from_document(id.clone(), document, self.policy)?;
        Ok((client, ttl))
    }

    fn keep(&self, id: &ClientId, client: Option<Client>, until: Instant, now: Instant) {
        let mut cache = self.cache.lock().unwrap();
        if cache.len() >= MAX_ENTRIES && !cache.contains_key(id) {
            cache.retain(|_, cached| cached.until > now);
            if cache.len() >= MAX_ENTRIES
                && let Some(soonest) = cache
                    .iter()
                    .min_by_key(|(_, cached)| cached.until)
                    .map(|(id, _)| id.clone())
            {
                cache.remove(&soonest);
            }
        }
        cache.insert(id.clone(), Cached { client, until });
    }
}

/// How long a document is kept: its `max-age`, within bounds that spare a client neither a
/// refetch per sign-in nor a day-long wait for a fixed document.
fn ttl_of(cache_control: Option<&str>) -> Duration {
    cache_control
        .into_iter()
        .flat_map(|value| value.split(','))
        .find_map(|directive| directive.trim().strip_prefix("max-age="))
        .and_then(|seconds| seconds.trim().parse::<u64>().ok())
        .map_or(MIN_TTL, |seconds| {
            Duration::from_secs(seconds).clamp(MIN_TTL, MAX_TTL)
        })
}

#[async_trait::async_trait]
impl Clients for MetadataClients {
    async fn find(&self, id: &ClientId) -> Result<Option<Client>, AuthError> {
        Ok(self.find_at(id, Instant::now()).await)
    }
}

#[cfg(test)]
mod tests;
