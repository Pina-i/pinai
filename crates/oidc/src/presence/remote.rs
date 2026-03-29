//! RemotePresenceRegistry — manages outbound SSE connections (for active conversations)
//! and batch polling (for the friends list sidebar) to remote IdP instances.
//!
//! ## Tiered hybrid model
//!
//! - **Active conversation**: SSE connection per involved remote domain (real-time typing + presence).
//! - **Friends list sidebar**: Batch poll `POST /api/presence/batch` every ~10s per remote domain.
//!
//! When no user has an active conversation involving a remote domain, the SSE connection is closed.
//! Batch polling runs independently on a fixed interval for all remote domains that have friends.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use idp_broker::EventBroker;
use idp_db::repos::friendships;
use idp_db::PgPool;
use tracing::{info, warn};

use super::store::PresenceStore;
use super::types::{PresenceBatchRequest, PresenceResponse};

/// How often to batch-poll remote domains for sidebar presence.
const BATCH_POLL_INTERVAL: Duration = Duration::from_secs(10);

/// Manages outbound connections to remote IdP instances for presence.
pub struct RemotePresenceRegistry {
    /// Domains to batch-poll (all remote domains with at least one friendship).
    /// Maps domain → set of actor_uris to poll.
    batch_poll_domains: DashMap<String, HashSet<String>>,
}

impl RemotePresenceRegistry {
    pub fn new() -> Self {
        Self {
            batch_poll_domains: DashMap::new(),
        }
    }

    /// Register remote actors for batch polling.
    /// Called when friendships change (new friend accepted, friend removed).
    pub fn register_for_batch_poll(&self, domain: &str, actor_uris: Vec<String>) {
        let mut entry = self.batch_poll_domains.entry(domain.to_string()).or_default();
        for uri in actor_uris {
            entry.insert(uri);
        }
    }

    /// Remove a remote actor from batch polling.
    pub fn unregister_from_batch_poll(&self, domain: &str, actor_uri: &str) {
        if let Some(mut entry) = self.batch_poll_domains.get_mut(domain) {
            entry.remove(actor_uri);
            if entry.is_empty() {
                drop(entry);
                self.batch_poll_domains.remove(domain);
            }
        }
    }

    /// Get all domains and their actor sets for batch polling.
    pub fn batch_poll_snapshot(&self) -> HashMap<String, Vec<String>> {
        self.batch_poll_domains
            .iter()
            .map(|entry| {
                (
                    entry.key().clone(),
                    entry.value().iter().cloned().collect(),
                )
            })
            .collect()
    }
}

/// Run the batch poller as a long-lived background task.
///
/// Every ~10 seconds, iterates all remote domains in the registry and polls
/// `POST /api/presence/batch` on each, updating the local PresenceStore.
pub async fn run_batch_poller(
    registry: Arc<RemotePresenceRegistry>,
    store: Arc<PresenceStore>,
    broker: Arc<dyn EventBroker>,
    pool: PgPool,
    keypair: Arc<jwt_utils::EdKeyPair>,
    config: Arc<idp_config::Config>,
) {
    // On startup, populate the registry from existing friendships.
    populate_registry_from_db(&registry, &pool, &config).await;

    loop {
        tokio::time::sleep(BATCH_POLL_INTERVAL).await;

        let domains = registry.batch_poll_snapshot();
        if domains.is_empty() {
            continue;
        }

        for (domain, actor_uris) in &domains {
            if actor_uris.is_empty() {
                continue;
            }

            match batch_poll_domain(domain, actor_uris, &keypair, &config).await {
                Ok(response) => {
                    let channel = format!("presence:{}", config.domain);
                    for ap in &response.presence {
                        let old = store.get(&ap.actor_uri);
                        store.set(&ap.actor_uri, ap.state);

                        // If state changed, publish to local Redis so WS fanout picks it up.
                        if old != ap.state {
                            let event = super::types::PresenceEvent {
                                kind: "presence".to_string(),
                                event: ap.state,
                                actor_uri: ap.actor_uri.clone(),
                                timestamp: time::OffsetDateTime::now_utc()
                                    .format(
                                        &time::format_description::well_known::Rfc3339,
                                    )
                                    .unwrap_or_default(),
                            };
                            if let Ok(payload) = serde_json::to_string(&event) {
                                let _ = broker.publish_presence(&channel, &payload).await;
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!(domain = %domain, "batch presence poll failed: {e}");
                }
            }
        }
    }
}

/// Populate the registry from existing accepted friendships with remote actors.
async fn populate_registry_from_db(
    registry: &RemotePresenceRegistry,
    pool: &PgPool,
    config: &idp_config::Config,
) {
    let issuer = config.issuer();

    let actor_uris = match friendships::get_all_friend_actor_uris(pool).await {
        Ok(uris) => uris,
        Err(e) => {
            warn!("failed to load friendships for presence registry: {e}");
            return;
        }
    };

    let mut by_domain: HashMap<String, Vec<String>> = HashMap::new();
    for uri in actor_uris {
        // Skip local actors
        if uri.starts_with(&issuer) {
            continue;
        }
        // Extract domain from actor_uri: https://domain/users/...
        if let Some(domain) = extract_domain_from_actor_uri(&uri) {
            by_domain.entry(domain).or_default().push(uri);
        }
    }

    for (domain, uris) in by_domain {
        registry.register_for_batch_poll(&domain, uris);
    }

    info!(
        domain_count = registry.batch_poll_domains.len(),
        "populated remote presence registry from DB"
    );
}

/// Extract the domain (host + optional port) from an actor URI.
fn extract_domain_from_actor_uri(uri: &str) -> Option<String> {
    let url = url::Url::parse(uri).ok()?;
    let host = url.host_str()?;
    match url.port() {
        Some(port) => Some(format!("{host}:{port}")),
        None => Some(host.to_string()),
    }
}

/// Poll a single remote domain for batch presence.
async fn batch_poll_domain(
    domain: &str,
    actor_uris: &[String],
    keypair: &jwt_utils::EdKeyPair,
    config: &idp_config::Config,
) -> Result<PresenceResponse, Box<dyn std::error::Error + Send + Sync>> {
    let scheme = if domain.starts_with("localhost") || domain.starts_with("127.") {
        "http"
    } else {
        "https"
    };
    let url = format!("{scheme}://{domain}/api/presence/batch");
    let path = "/api/presence/batch";

    let body = PresenceBatchRequest {
        actors: actor_uris.to_vec(),
    };
    let body_json = serde_json::to_vec(&body)?;

    // Sign the request with HTTP Signatures
    let date = http_signatures::http_date_now();
    let digest = http_signatures::sha256_digest(&body_json);
    let key_id = format!("{}/actor#main-key", config.issuer());

    let signature = http_signatures::sign_request(http_signatures::SignParams {
        method: "post",
        path,
        host: domain,
        date: &date,
        digest: Some(&digest),
        key_id: &key_id,
        signing_key: &keypair.signing_key,
    })?;

    let client = reqwest::Client::new();
    let response = client
        .post(&url)
        .header("Host", domain)
        .header("Date", &date)
        .header("Digest", &digest)
        .header("Signature", &signature)
        .header("Content-Type", "application/json")
        .body(body_json)
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(format!("HTTP {}", response.status()).into());
    }

    let result: PresenceResponse = response.json().await?;
    Ok(result)
}
