use std::sync::Arc;

use connections::Hub;
use domain::UserId;
use domain::settings::{SettingsDocument, SettingsNotifier};

use super::events::{SettingsPayload, WsEvent};

/// Pushes `settings_updated` to every live session of the account.
pub struct HubSettingsNotifier {
    hub: Arc<Hub>,
}

impl HubSettingsNotifier {
    pub fn new(hub: Arc<Hub>) -> Self {
        Self { hub }
    }
}

impl SettingsNotifier for HubSettingsNotifier {
    fn settings_updated(&self, user: UserId, settings: &SettingsDocument) {
        super::push(
            &self.hub,
            &user.as_uuid(),
            WsEvent::SettingsUpdated(SettingsPayload {
                settings: settings.as_value().clone(),
            }),
        );
    }
}
