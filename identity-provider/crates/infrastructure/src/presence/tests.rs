use domain::ConversationId;
use domain::identity::testing::account;
use domain::presence::{PresenceEvent, PresenceState, TypingEvent};
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::*;

fn at() -> OffsetDateTime {
    OffsetDateTime::parse("2026-09-29T12:00:00Z", &Rfc3339).unwrap()
}

#[test]
fn a_presence_state_travels_on_the_domains_channel_in_the_documented_envelope() {
    let alice = account("alice").actor_uri;
    let signal = Signal::Presence(PresenceEvent {
        actor: alice.clone(),
        state: PresenceState::Dnd,
        at: at(),
    });

    let (channel, payload) = encode("idp.alice.test", &signal).unwrap();

    assert_eq!(channel, "presence:idp.alice.test");
    assert_eq!(
        serde_json::from_str::<Value>(&payload).unwrap(),
        json!({
            "type": "presence",
            "event": "dnd",
            "actorUri": alice.as_str(),
            "timestamp": "2026-09-29T12:00:00Z",
        })
    );
    assert_eq!(decode(&channel, &payload), Some(signal));
}

#[test]
fn typing_travels_on_its_conversations_channel() {
    let alice = account("alice").actor_uri;
    let conversation = ConversationId::generate();
    let signal = Signal::Typing(TypingEvent {
        actor: alice.clone(),
        conversation,
        at: at(),
    });

    let (channel, payload) = encode("idp.alice.test", &signal).unwrap();

    assert_eq!(channel, format!("typing:{conversation}"));
    assert_eq!(
        serde_json::from_str::<Value>(&payload).unwrap(),
        json!({
            "type": "typing",
            "actorUri": alice.as_str(),
            "conversationId": conversation.to_string(),
            "timestamp": "2026-09-29T12:00:00Z",
        })
    );
    assert_eq!(decode(&channel, &payload), Some(signal));
}

#[test]
fn a_malformed_signal_is_nothing() {
    assert_eq!(decode("presence:x", "not json"), None);
    assert_eq!(
        decode(
            "presence:x",
            r#"{"type":"presence","event":"online","actorUri":"not a uri","timestamp":"2026-09-29T12:00:00Z"}"#
        ),
        None
    );
    assert_eq!(decode("elsewhere", "{}"), None);
}
