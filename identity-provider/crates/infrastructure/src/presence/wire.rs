use anyhow::Context;
use domain::ConversationId;
use domain::identity::ActorUri;
use domain::presence::{PresenceError, PresenceEvent, Signal, TypingEvent};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PresenceJson {
    #[serde(rename = "type")]
    kind: String,
    event: String,
    actor_uri: String,
    timestamp: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TypingJson {
    #[serde(rename = "type")]
    kind: String,
    actor_uri: String,
    conversation_id: uuid::Uuid,
    timestamp: String,
}

fn rfc3339(at: OffsetDateTime) -> Result<String, PresenceError> {
    Ok(at.format(&Rfc3339).context("format a signal's time")?)
}

/// A signal as the bus and a peer's stream carry it.
pub(crate) fn encode(signal: &Signal) -> Result<String, PresenceError> {
    let json = match signal {
        Signal::Presence(event) => serde_json::to_string(&PresenceJson {
            kind: "presence".to_owned(),
            event: event.state.as_str().to_owned(),
            actor_uri: event.actor.to_string(),
            timestamp: rfc3339(event.at)?,
        }),
        Signal::Typing(event) => serde_json::to_string(&TypingJson {
            kind: "typing".to_owned(),
            actor_uri: event.actor.to_string(),
            conversation_id: event.conversation.as_uuid(),
            timestamp: rfc3339(event.at)?,
        }),
    };
    Ok(json.context("encode a signal")?)
}

fn at(timestamp: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(timestamp, &Rfc3339).ok()
}

/// `None` for anything malformed.
pub(crate) fn decode_presence(json: &str) -> Option<Signal> {
    let event: PresenceJson = serde_json::from_str(json).ok()?;
    Some(Signal::Presence(PresenceEvent {
        actor: ActorUri::parse(&event.actor_uri).ok()?,
        state: event.event.parse().ok()?,
        at: at(&event.timestamp)?,
    }))
}

/// `None` for anything malformed.
pub(crate) fn decode_typing(json: &str) -> Option<Signal> {
    let event: TypingJson = serde_json::from_str(json).ok()?;
    Some(Signal::Typing(TypingEvent {
        actor: ActorUri::parse(&event.actor_uri).ok()?,
        conversation: ConversationId::from(event.conversation_id),
        at: at(&event.timestamp)?,
    }))
}
