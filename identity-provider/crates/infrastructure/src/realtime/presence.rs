use std::sync::Arc;

use connections::Hub;
use domain::UserId;
use domain::presence::{PresenceEvent, PresenceNotifier, TypingEvent};
use time::format_description::well_known::Rfc3339;

use super::events::{PresenceUpdatePayload, TypingPayload, WsEvent};

/// Pushes presence and typing to an account's live sessions only: both are ephemeral, and a
/// client reloads presence on connect.
pub struct HubPresenceNotifier {
    hub: Arc<Hub>,
}

impl HubPresenceNotifier {
    pub fn new(hub: Arc<Hub>) -> Self {
        Self { hub }
    }
}

impl PresenceNotifier for HubPresenceNotifier {
    fn presence(&self, to: UserId, event: &PresenceEvent) {
        super::push(
            &self.hub,
            &to.as_uuid(),
            WsEvent::PresenceUpdate(PresenceUpdatePayload {
                actor_uri: event.actor.to_string(),
                state: event.state.as_str().to_owned(),
                timestamp: event.at.format(&Rfc3339).unwrap_or_default(),
            }),
        );
    }

    fn typing(&self, to: UserId, event: &TypingEvent) {
        super::push(
            &self.hub,
            &to.as_uuid(),
            WsEvent::Typing(TypingPayload {
                actor_uri: event.actor.to_string(),
                conversation_id: event.conversation.as_uuid(),
                timestamp: event.at.format(&Rfc3339).unwrap_or_default(),
            }),
        );
    }
}
