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
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing::{info, warn};
use uuid::Uuid;

use super::sse_client;
use super::store::PresenceStore;
use super::types::{PresenceBatchRequest, PresenceResponse};

/// How often to batch-poll remote domains for sidebar presence.
const BATCH_POLL_INTERVAL: Duration = Duration::from_secs(10);

/// Per-domain SSE state. The connection is alive while at least one
/// conversation has registered itself as a watcher.
struct ActiveSse {
    /// conversation_id → set of remote actor_uris that conversation cares about.
    watchers: HashMap<Uuid, HashSet<String>>,
    /// Background task running the SSE connection. Aborted on close/restart.
    task: JoinHandle<()>,
}

/// Optional dependencies the SSE consumer needs to sign requests and
/// republish events. Wired at startup via `set_sse_deps`.
#[derive(Clone)]
struct SseDeps {
    keypair: Arc<jwt_utils::EdKeyPair>,
    config: Arc<idp_config::Config>,
    broker: Arc<dyn EventBroker>,
}

/// Manages outbound connections to remote IdP instances for presence.
pub struct RemotePresenceRegistry {
    /// Domains to batch-poll (all remote domains with at least one friendship).
    /// Maps domain → set of actor_uris to poll.
    batch_poll_domains: DashMap<String, HashSet<String>>,
    /// Active SSE connections for conversations currently watched by local users.
    active_sse: Mutex<HashMap<String, ActiveSse>>,
    /// Lazily-initialised deps for spawning SSE tasks.
    sse_deps: std::sync::OnceLock<SseDeps>,
}

impl RemotePresenceRegistry {
    pub fn new() -> Self {
        Self {
            batch_poll_domains: DashMap::new(),
            active_sse: Mutex::new(HashMap::new()),
            sse_deps: std::sync::OnceLock::new(),
        }
    }

    /// Wire the dependencies the SSE consumer needs. Call once at startup.
    pub fn set_sse_deps(
        &self,
        keypair: Arc<jwt_utils::EdKeyPair>,
        config: Arc<idp_config::Config>,
        broker: Arc<dyn EventBroker>,
    ) {
        let _ = self.sse_deps.set(SseDeps {
            keypair,
            config,
            broker,
        });
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

    /// Register a newly-accepted friend's actor URI for batch polling
    /// if it points at a remote domain. Local actors are a no-op —
    /// their presence is already in this IdP's local store via the WS
    /// `set_presence` path. Without this, a freshly-accepted remote
    /// friend stays "Offline" in the local snapshot until the next
    /// IdP restart (where `populate_registry_from_db` would pick them
    /// up on startup).
    pub fn register_friend(&self, actor_uri: &str, local_issuer: &str) {
        if actor_uri.starts_with(local_issuer) {
            return;
        }
        if let Some(domain) = extract_domain_from_actor_uri(actor_uri) {
            self.register_for_batch_poll(&domain, vec![actor_uri.to_string()]);
        }
    }

    /// Inverse of `register_friend`: drop a removed friend from batch
    /// polling so we don't keep hitting the remote IdP for someone we
    /// no longer have a relationship with.
    pub fn unregister_friend(&self, actor_uri: &str, local_issuer: &str) {
        if actor_uri.starts_with(local_issuer) {
            return;
        }
        if let Some(domain) = extract_domain_from_actor_uri(actor_uri) {
            self.unregister_from_batch_poll(&domain, actor_uri);
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

    /// Mark a conversation as actively watched by a local user. Ensures an
    /// outbound SSE connection exists for every remote domain involved.
    ///
    /// `remote_actors_by_domain` lists the conversation's remote members
    /// grouped by their domain — local members are excluded by the caller.
    pub async fn watch_conversation(
        self: &Arc<Self>,
        conv_id: Uuid,
        remote_actors_by_domain: HashMap<String, Vec<String>>,
    ) {
        let mut active = self.active_sse.lock().await;
        for (domain, actors) in remote_actors_by_domain {
            // Track this conversation's interest under this domain.
            let entry = active.entry(domain.clone()).or_insert_with(|| ActiveSse {
                watchers: HashMap::new(),
                task: tokio::spawn(async {}),
            });
            entry
                .watchers
                .entry(conv_id)
                .or_default()
                .extend(actors.iter().cloned());

            // Restart the SSE task with the union of all watcher actors.
            self.respawn_sse(&mut active, &domain).await;
        }
    }

    /// Drop a conversation's interest in remote presence/typing. Closes the
    /// SSE connection for any domain that no longer has any watchers.
    pub async fn unwatch_conversation(self: &Arc<Self>, conv_id: Uuid) {
        let mut active = self.active_sse.lock().await;
        let domains: Vec<String> = active.keys().cloned().collect();
        for domain in domains {
            let still_needed = if let Some(entry) = active.get_mut(&domain) {
                entry.watchers.remove(&conv_id);
                !entry.watchers.is_empty()
            } else {
                false
            };

            if still_needed {
                self.respawn_sse(&mut active, &domain).await;
            } else if let Some(entry) = active.remove(&domain) {
                entry.task.abort();
                info!(%domain, "SSE: closed (no remaining watchers)");
            }
        }
    }

    /// Replace the running SSE task for `domain` with a fresh one whose actor
    /// list is the union of every watcher's actors. Caller holds the lock.
    async fn respawn_sse(
        self: &Arc<Self>,
        active: &mut HashMap<String, ActiveSse>,
        domain: &str,
    ) {
        let Some(entry) = active.get_mut(domain) else {
            return;
        };

        let mut union: HashSet<String> = HashSet::new();
        for actors in entry.watchers.values() {
            for a in actors {
                union.insert(a.clone());
            }
        }
        let actor_uris: Vec<String> = union.into_iter().collect();

        // Cancel previous task before spawning a new one.
        entry.task.abort();

        let Some(deps) = self.sse_deps.get().cloned() else {
            warn!("SSE: deps not initialized; dropping watch");
            return;
        };
        let domain_owned = domain.to_string();
        info!(
            domain = %domain_owned,
            actor_count = actor_uris.len(),
            watcher_count = entry.watchers.len(),
            "SSE: (re)opening connection"
        );
        let task = tokio::spawn(sse_client::run_sse_connection(
            domain_owned,
            actor_uris,
            deps.keypair,
            deps.config,
            deps.broker,
        ));
        entry.task = task;
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
    let scheme = config.scheme();
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
