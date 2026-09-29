use std::sync::Arc;

use domain::UserId;
use domain::presence::{PresenceEvent, PresenceNotifier, TypingEvent};
use idp_realtime::{PresenceUpdatePayload, TypingPayload, WsEvent, WsHub};
use time::format_description::well_known::Rfc3339;

/// Pushes presence and typing to an account's live sessions only: both are ephemeral, and a
/// client reloads presence on connect.
pub struct HubPresenceNotifier {
    hub: Arc<WsHub>,
}

impl HubPresenceNotifier {
    pub fn new(hub: Arc<WsHub>) -> Self {
        Self { hub }
    }
}

impl PresenceNotifier for HubPresenceNotifier {
    fn presence(&self, to: UserId, event: &PresenceEvent) {
        self.hub.send_to_user(
            &to.as_uuid(),
            WsEvent::PresenceUpdate(PresenceUpdatePayload {
                actor_uri: event.actor.to_string(),
                state: event.state.as_str().to_owned(),
                timestamp: event.at.format(&Rfc3339).unwrap_or_default(),
            }),
        );
    }

    fn typing(&self, to: UserId, event: &TypingEvent) {
        self.hub.send_to_user(
            &to.as_uuid(),
            WsEvent::Typing(TypingPayload {
                actor_uri: event.actor.to_string(),
                conversation_id: event.conversation.as_uuid(),
                timestamp: event.at.format(&Rfc3339).unwrap_or_default(),
            }),
        );
    }
}
