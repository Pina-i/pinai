//! Presence from other instances: the batch poll behind a friends list, and the streams behind an
//! open conversation — identity-provider/specs/presence.md § Cross-instance presence.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context;
use domain::ConversationId;
use domain::identity::{ActorUri, Domain, InstanceOrigin};
use domain::presence::{PeerPresence, PeerStreams, PresenceError, PresenceState, Signal};
use federation_transport::http::read_capped;
use federation_transport::{Signer, UrlPolicy, send_signed_post, signed_get};
use futures_core::stream::BoxStream;
use jwt_utils::EdKeyPair;
use serde::Deserialize;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::presence::{decode_presence, decode_typing};

const RECONNECT_INITIAL: Duration = Duration::from_secs(2);
const RECONNECT_MAX: Duration = Duration::from_secs(30);

/// Asks as the instance: the peer answers for the accounts its own users may see.
fn key_id(origin: &InstanceOrigin) -> String {
    format!("{}/actor#main-key", origin.base_url())
}

/// `POST /api/presence/batch` on the peer, signed as this instance.
pub struct SignedPeerPresence {
    keypair: Arc<EdKeyPair>,
    origin: InstanceOrigin,
    policy: UrlPolicy,
}

impl SignedPeerPresence {
    pub fn new(keypair: Arc<EdKeyPair>, origin: InstanceOrigin, policy: UrlPolicy) -> Self {
        Self {
            keypair,
            origin,
            policy,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ActorPresenceDto {
    actor_uri: String,
    state: String,
}

#[derive(Deserialize)]
struct BatchDto {
    presence: Vec<ActorPresenceDto>,
}

#[async_trait::async_trait]
impl PeerPresence for SignedPeerPresence {
    async fn poll(
        &self,
        peer: &Domain,
        actors: &[ActorUri],
    ) -> Result<Vec<(ActorUri, PresenceState)>, PresenceError> {
        let url = format!("{}://{peer}/api/presence/batch", self.origin.scheme());
        let body = serde_json::to_vec(&serde_json::json!({
            "actors": actors.iter().map(ActorUri::as_str).collect::<Vec<_>>(),
        }))
        .context("encode a presence poll")?;
        let key_id = key_id(&self.origin);
        let signer = Signer {
            key_id: &key_id,
            signing_key: &self.keypair.signing_key,
        };
        // The shared client: screened, 5 s at most, and a capped answer. A refusal is logged
        // once, by the poll, rather than by `signed_post` too.
        let response = send_signed_post(&signer, &url, &body, "application/json", self.policy)
            .await
            .context("poll a peer's presence")?;
        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "the peer answered a presence poll with {}",
                response.status()
            )
            .into());
        }
        let answer = read_capped(response)
            .await
            .context("read a peer's presence")?;
        let answer: BatchDto =
            serde_json::from_slice(&answer).context("decode a peer's presence")?;
        Ok(answer
            .presence
            .into_iter()
            .filter_map(|entry| {
                Some((
                    ActorUri::parse(&entry.actor_uri).ok()?,
                    entry.state.parse().ok()?,
                ))
            })
            .collect())
    }
}

/// One `GET /api/presence/stream` per peer instance, asking for the union of the remote members
/// of every conversation watched here; what it carries comes out of the stream `new` returns.
pub struct SsePeerStreams {
    source: Arc<Source>,
    active: Mutex<HashMap<Domain, Followed>>,
}

struct Source {
    keypair: Arc<EdKeyPair>,
    origin: InstanceOrigin,
    policy: UrlPolicy,
    heard: mpsc::UnboundedSender<(Domain, Signal)>,
}

#[derive(Default)]
struct Followed {
    watchers: HashMap<ConversationId, HashSet<ActorUri>>,
    task: Option<JoinHandle<()>>,
}

impl Followed {
    fn actors(&self) -> HashSet<ActorUri> {
        self.watchers.values().flatten().cloned().collect()
    }

    fn follow(&mut self, source: &Arc<Source>, peer: &Domain) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
        let actors: Vec<ActorUri> = self.actors().into_iter().collect();
        tracing::info!(%peer, actors = actors.len(), "presence stream from a peer (re)opened");
        self.task = Some(tokio::spawn(follow(source.clone(), peer.clone(), actors)));
    }
}

impl SsePeerStreams {
    pub fn new(
        keypair: Arc<EdKeyPair>,
        origin: InstanceOrigin,
        policy: UrlPolicy,
    ) -> (Self, BoxStream<'static, (Domain, Signal)>) {
        let (heard, mut received) = mpsc::unbounded_channel();
        let streams = Self {
            source: Arc::new(Source {
                keypair,
                origin,
                policy,
                heard,
            }),
            active: Mutex::default(),
        };
        let received = futures_util::stream::poll_fn(move |cx| received.poll_recv(cx));
        (streams, Box::pin(received))
    }
}

#[async_trait::async_trait]
impl PeerStreams for SsePeerStreams {
    async fn watch(&self, conversation: ConversationId, members: HashMap<Domain, Vec<ActorUri>>) {
        let mut active = self.active.lock().unwrap();
        for (peer, actors) in members {
            let followed = active.entry(peer.clone()).or_default();
            // The peer settles which conversations' typing it streams on connect: a new one
            // needs a new stream even when its members are followed already.
            let known = followed.watchers.contains_key(&conversation);
            let before = followed.actors();
            followed
                .watchers
                .entry(conversation)
                .or_default()
                .extend(actors);
            if followed.task.is_none() || !known || followed.actors() != before {
                followed.follow(&self.source, &peer);
            }
        }
    }

    async fn unwatch(&self, conversation: ConversationId) {
        let mut active = self.active.lock().unwrap();
        active.retain(|peer, followed| {
            let before = followed.actors();
            if followed.watchers.remove(&conversation).is_none() {
                return true;
            }
            if followed.watchers.is_empty() {
                if let Some(task) = followed.task.take() {
                    task.abort();
                }
                tracing::info!(%peer, "presence stream from a peer closed");
                return false;
            }
            if followed.actors() != before {
                followed.follow(&self.source, peer);
            }
            true
        });
    }
}

/// Until aborted: a dropped stream is opened again, backing off up to 30 s.
async fn follow(source: Arc<Source>, peer: Domain, actors: Vec<ActorUri>) {
    let mut backoff = RECONNECT_INITIAL;
    loop {
        match source.stream(&peer, &actors).await {
            Ok(()) => backoff = RECONNECT_INITIAL,
            Err(e) => {
                tracing::warn!(%peer, error = ?e, ?backoff, "presence stream from a peer ended")
            }
        }
        if source.heard.is_closed() {
            return;
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(RECONNECT_MAX);
    }
}

impl Source {
    async fn stream(&self, peer: &Domain, actors: &[ActorUri]) -> anyhow::Result<()> {
        let mut url = url::Url::parse(&format!(
            "{}://{peer}/api/presence/stream",
            self.origin.scheme()
        ))
        .context("a peer's presence stream URL")?;
        url.query_pairs_mut()
            .extend_pairs(actors.iter().map(|actor| ("actors[]", actor.as_str())));
        let key_id = key_id(&self.origin);
        let signer = Signer {
            key_id: &key_id,
            signing_key: &self.keypair.signing_key,
        };
        // The download client: screened, no redirect, no total timeout — a stream stays open —
        // but 30 s without a byte, two keep-alives missed, ends it.
        let mut response = signed_get(&signer, url.as_str(), self.policy)
            .await
            .context("open a peer's presence stream")?;
        let mut frames = Frames::default();
        while let Some(chunk) = response
            .chunk()
            .await
            .context("read a peer's presence stream")?
        {
            for frame in frames.push(&chunk) {
                let Some(signal) = read_frame(&frame) else {
                    continue;
                };
                if self.heard.send((peer.clone(), signal)).is_err() {
                    return Ok(());
                }
            }
        }
        Ok(())
    }
}

/// Server-sent events cut into frames, each ending at a blank line.
#[derive(Default)]
struct Frames {
    buffer: Vec<u8>,
}

impl Frames {
    fn push(&mut self, chunk: &[u8]) -> Vec<String> {
        self.buffer.extend_from_slice(chunk);
        let mut frames = Vec::new();
        loop {
            let lf = self.buffer.windows(2).position(|w| w == b"\n\n");
            let crlf = self.buffer.windows(4).position(|w| w == b"\r\n\r\n");
            let (end, separator) = match (lf, crlf) {
                (Some(lf), Some(crlf)) if crlf < lf => (crlf, 4),
                (Some(lf), _) => (lf, 2),
                (None, Some(crlf)) => (crlf, 4),
                (None, None) => return frames,
            };
            let frame: Vec<u8> = self.buffer.drain(..end + separator).collect();
            frames.push(String::from_utf8_lossy(&frame[..end]).into_owned());
        }
    }
}

/// A `presence` or `typing` event; comments, keep-alives and anything malformed are nothing.
fn read_frame(frame: &str) -> Option<Signal> {
    let mut event = None;
    let mut data = Vec::new();
    for line in frame.lines() {
        if let Some(name) = line.strip_prefix("event:") {
            event = Some(name.trim());
        } else if let Some(line) = line.strip_prefix("data:") {
            data.push(line.strip_prefix(' ').unwrap_or(line));
        }
    }
    let data = data.join("\n");
    let signal = match event? {
        "presence" => decode_presence(&data),
        "typing" => decode_typing(&data),
        _ => return None,
    };
    if signal.is_none() {
        tracing::warn!(event = ?event, "malformed signal on a peer's presence stream");
    }
    signal
}

#[cfg(test)]
mod tests;
