//! Inter-IdP SSE stream endpoint.
//!
//! `GET /api/presence/stream?actors[]=...`
//!
//! A remote IdP connects once per domain to receive real-time presence and typing
//! events for the requested actors. Authenticated via HTTP Signatures.

use std::collections::HashSet;
use std::convert::Infallible;
use std::time::Duration;

use axum::{
    extract::{RawQuery, State},
    http::HeaderMap,
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse,
    },
};
use tokio::sync::mpsc;
use tracing::info;
use uuid::Uuid;

use crate::error::OidcError;
use crate::AppState;

use super::handlers::{parse_actors_query, verify_http_signature};
use super::types::{PresenceEvent, TypingEvent};

/// `GET /api/presence/stream?actors[]=...`
///
/// HTTP Signature auth. Returns a persistent SSE stream filtered to the requested actors.
/// The two subsystems are distinguished by the SSE `event:` field (`presence` or `typing`).
#[tracing::instrument(skip_all, fields(actor_count))]
pub async fn get_presence_stream(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(raw): RawQuery,
) -> Result<impl IntoResponse, OidcError> {
    // Verify HTTP Signature against the raw query string so the signed
    // `(request-target)` matches what the client sent.
    let path = match raw.as_deref() {
        Some(q) => format!("/api/presence/stream?{q}"),
        None => "/api/presence/stream".to_string(),
    };
    verify_http_signature(&state, &headers, "get", &path).await?;

    let actors: HashSet<String> = parse_actors_query(raw.as_deref()).into_iter().collect();
    tracing::Span::current().record("actor_count", actors.len());

    if actors.is_empty() {
        return Err(OidcError::invalid_request("actors[] parameter is required"));
    }

    // Replay last known presence state on connect (or reconnect via Last-Event-ID)
    let store = state
        .presence_store
        .as_ref()
        .ok_or_else(|| OidcError::server_error("presence not available"))?;

    let actor_list: Vec<String> = actors.iter().cloned().collect();

    // Determine which typing channels to subscribe to.
    // Subscribe to typing:<convId> for conversations where at least one participant
    // is local AND the other is one of the requested remote actors.
    let typing_channels = resolve_typing_channels(&state, &actor_list).await;

    // Subscribe to Redis pub-sub for presence and relevant typing channels.
    let presence_channel = format!("presence:{}", state.config.domain);
    let channels: Vec<&str> = std::iter::once(presence_channel.as_str())
        .chain(typing_channels.iter().map(|s| s.as_str()))
        .collect();

    let mut redis_rx = idp_broker::subscribe_channels(&state.config.redis_url, &channels, &[])
        .await
        .map_err(|e| OidcError::server_error(format!("failed to subscribe: {e}")))?;

    // Create the SSE output channel.
    let (sse_tx, sse_rx) = mpsc::unbounded_channel::<Result<Event, Infallible>>();

    // Replay current presence state for all requested actors.
    let snapshot = store.snapshot(&actor_list);
    for (actor_uri, presence_state, _instant) in snapshot {
        let event = PresenceEvent {
            kind: "presence".to_string(),
            event: presence_state,
            actor_uri,
            timestamp: time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
        };

        if let Ok(data) = serde_json::to_string(&event) {
            let sse_event = Event::default()
                .id(Uuid::new_v4().to_string())
                .event("presence")
                .data(data);
            let _ = sse_tx.send(Ok(sse_event));
        }
    }

    // Background task: filter Redis messages and forward matching events to SSE.
    let actors_clone = actors.clone();
    tokio::spawn(async move {
        while let Some(msg) = redis_rx.recv().await {
            if msg.channel.starts_with("presence:") {
                // Filter: only forward events for actors in the requested set.
                if let Ok(event) = serde_json::from_str::<PresenceEvent>(&msg.payload) {
                    if !actors_clone.contains(&event.actor_uri) {
                        continue;
                    }
                    let sse_event = Event::default()
                        .id(Uuid::new_v4().to_string())
                        .event("presence")
                        .data(msg.payload);
                    if sse_tx.send(Ok(sse_event)).is_err() {
                        break; // Client disconnected
                    }
                }
            } else if msg.channel.starts_with("typing:") {
                // Filter: only forward typing events from requested actors.
                if let Ok(event) = serde_json::from_str::<TypingEvent>(&msg.payload) {
                    if !actors_clone.contains(&event.actor_uri) {
                        continue;
                    }
                    let sse_event = Event::default()
                        .id(Uuid::new_v4().to_string())
                        .event("typing")
                        .data(msg.payload);
                    if sse_tx.send(Ok(sse_event)).is_err() {
                        break;
                    }
                }
            }
        }
    });

    info!(actor_count = actors.len(), "SSE presence stream started");

    let stream = tokio_stream::wrappers::UnboundedReceiverStream::new(sse_rx);
    Ok(Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive"),
    ))
}

/// Resolve which `typing:<convId>` channels this SSE stream should subscribe to.
///
/// Finds conversations where at least one member is local AND another member is
/// one of the requested remote actors.
async fn resolve_typing_channels(state: &AppState, actor_uris: &[String]) -> Vec<String> {
    let mut channels = Vec::new();

    for actor_uri in actor_uris {
        // Look up conversations where this remote actor is a member.
        // For each, check if any other member is local (i.e. has a local user).
        // This is a simplified approach — for full correctness we'd do a single query.
        if let Ok(convs) =
            idp_db::repos::conversations::find_conversations_for_actor(&state.pool, actor_uri).await
        {
            for conv_id in convs {
                channels.push(format!("typing:{conv_id}"));
            }
        }
    }

    channels.dedup();
    channels
}
