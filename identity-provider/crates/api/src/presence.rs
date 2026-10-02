//! Presence snapshots, and what peers poll and stream — see identity-provider/specs/presence.md.

use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use application::presence::{OpenPeerStream, ReadPresence, ServePeerPresence};
use axum::Json;
use axum::extract::{RawQuery, State};
use axum::response::IntoResponse;
use axum::response::sse::{Event, KeepAlive, Sse};
use domain::identity::ActorUri;
use domain::presence::{PresenceError, PresenceState, Signal};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::ApiError;
use tokio_util::sync::CancellationToken;

use crate::auth::{Authenticated, SignedJson, SignedPeer};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActorPresenceBody {
    actor_uri: String,
    state: &'static str,
}

#[derive(Serialize)]
pub struct PresenceBody {
    presence: Vec<ActorPresenceBody>,
}

impl From<PresenceError> for ApiError {
    fn from(error: PresenceError) -> Self {
        match error {
            PresenceError::Unexpected(e) => ApiError::internal(e),
            other => ApiError::internal(anyhow::Error::from(other)),
        }
    }
}

/// Repeated `actors[]=` values: axum's query extractor keeps only one.
fn actors(raw: Option<&str>) -> Vec<String> {
    let Some(raw) = raw else {
        return Vec::new();
    };
    url::form_urlencoded::parse(raw.as_bytes())
        .filter(|(key, _)| key == "actors[]")
        .map(|(_, value)| value.into_owned())
        .collect()
}

fn parsed(asked: &[String]) -> Vec<ActorUri> {
    asked
        .iter()
        .filter_map(|actor| ActorUri::parse(actor).ok())
        .collect()
}

/// Every actor asked about, in the order asked: a string that is not an actor URI reads
/// `offline`, like an actor never heard of.
fn answer(asked: Vec<String>, states: Vec<(ActorUri, PresenceState)>) -> PresenceBody {
    let states: HashMap<String, PresenceState> = states
        .into_iter()
        .map(|(actor, state)| (actor.to_string(), state))
        .collect();
    PresenceBody {
        presence: asked
            .into_iter()
            .map(|actor| ActorPresenceBody {
                state: ActorUri::parse(&actor)
                    .ok()
                    .and_then(|uri| states.get(uri.as_str()).copied())
                    .unwrap_or(PresenceState::Offline)
                    .as_str(),
                actor_uri: actor,
            })
            .collect(),
    }
}

/// `GET /api/presence?actors[]=` — the states the client shows on load.
pub async fn read(
    State(read): State<Arc<ReadPresence>>,
    Authenticated(user): Authenticated,
    RawQuery(raw): RawQuery,
) -> Result<Json<PresenceBody>, ApiError> {
    let asked = actors(raw.as_deref());
    let states = read.execute(user, &parsed(&asked)).await?;
    Ok(Json(answer(asked, states)))
}

#[derive(Deserialize)]
pub struct BatchBody {
    actors: Vec<String>,
}

/// `POST /api/presence/batch` — a peer polling for its users' friends lists; the instance its
/// signing key belongs to is the peer.
pub async fn batch(
    State(serve): State<Arc<ServePeerPresence>>,
    SignedJson(peer, body): SignedJson<BatchBody>,
) -> Result<Json<PresenceBody>, ApiError> {
    let states = serve.execute(peer.domain(), &parsed(&body.actors)).await?;
    Ok(Json(answer(body.actors, states)))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PresenceSignalBody<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    event: &'static str,
    actor_uri: &'a str,
    timestamp: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TypingSignalBody<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    actor_uri: &'a str,
    conversation_id: String,
    timestamp: String,
}

/// One server-sent event: `event:` names the kind, `data:` carries the JSON.
fn event(signal: &Signal) -> Option<Event> {
    let (name, data) = match signal {
        Signal::Presence(presence) => (
            "presence",
            serde_json::to_string(&PresenceSignalBody {
                kind: "presence",
                event: presence.state.as_str(),
                actor_uri: presence.actor.as_str(),
                timestamp: presence.at.format(&Rfc3339).ok()?,
            }),
        ),
        Signal::Typing(typing) => (
            "typing",
            serde_json::to_string(&TypingSignalBody {
                kind: "typing",
                actor_uri: typing.actor.as_str(),
                conversation_id: typing.conversation.to_string(),
                timestamp: typing.at.format(&Rfc3339).ok()?,
            }),
        ),
    };
    Some(
        Event::default()
            .id(uuid::Uuid::new_v4().to_string())
            .event(name)
            .data(data.ok()?),
    )
}

/// `GET /api/presence/stream?actors[]=` — a peer following the accounts of a conversation open
/// there: the states heard first, then every change and typing indicator as it comes.
/// It ends when the instance stops, so the peer reopens it elsewhere.
pub async fn stream(
    State(open): State<Arc<OpenPeerStream>>,
    State(stop): State<CancellationToken>,
    SignedPeer(peer): SignedPeer,
    RawQuery(raw): RawQuery,
) -> Result<impl IntoResponse, ApiError> {
    let asked = parsed(&actors(raw.as_deref()));
    if asked.is_empty() {
        return Err(ApiError::bad_request("actors[] parameter is required"));
    }
    let stream = open
        .execute(peer.domain(), &asked, OffsetDateTime::now_utc())
        .await?;
    let events = futures_util::stream::iter(stream.replay.into_iter().map(Signal::Presence))
        .chain(stream.live)
        .take_until(stop.cancelled_owned())
        .filter_map(|signal| std::future::ready(event(&signal).map(Ok::<_, Infallible>)));
    Ok(Sse::new(events).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive"),
    ))
}

#[cfg(test)]
mod tests;
