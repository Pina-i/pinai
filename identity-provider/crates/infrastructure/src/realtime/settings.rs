use std::sync::Arc;

use domain::UserId;
use domain::settings::{SettingsDocument, SettingsNotifier};
use idp_realtime::{SettingsPayload, WsEvent, WsHub};

/// Pushes `settings_updated` to every live session of the account.
pub struct HubSettingsNotifier {
    hub: Arc<WsHub>,
}

impl HubSettingsNotifier {
    pub fn new(hub: Arc<WsHub>) -> Self {
        Self { hub }
    }
}

impl SettingsNotifier for HubSettingsNotifier {
    fn settings_updated(&self, user: UserId, settings: &SettingsDocument) {
        self.hub.send_to_user(
            &user.as_uuid(),
            WsEvent::SettingsUpdated(SettingsPayload {
                settings: settings.as_value().clone(),
            }),
        );
    }
}
