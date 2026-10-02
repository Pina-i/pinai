use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use connections::Hub;
use domain::e2ee::{DeviceNotifier, DeviceRootKey};
use domain::identity::ActorUri;
use domain::{DeviceId, UserId};

use super::events::{DeviceJoinedPayload, KeyPackagesLowPayload, WsEvent};

/// Tells the owner's live sessions, which add a new device to their groups and top up a low
/// stash; an offline device reconciles from the device list and its stash when it connects.
pub struct HubDeviceNotifier {
    hub: Arc<Hub>,
}

impl HubDeviceNotifier {
    pub fn new(hub: Arc<Hub>) -> Self {
        Self { hub }
    }
}

impl DeviceNotifier for HubDeviceNotifier {
    fn device_joined(
        &self,
        owner: UserId,
        actor: &ActorUri,
        device: DeviceId,
        key: &DeviceRootKey,
    ) {
        super::push(
            &self.hub,
            &owner.as_uuid(),
            WsEvent::DeviceJoined(DeviceJoinedPayload {
                actor_uri: actor.to_string(),
                device_id: device.as_uuid(),
                drk_public_key: B64.encode(key.as_bytes()),
            }),
        );
    }

    fn key_packages_low(&self, owner: UserId) {
        super::push(
            &self.hub,
            &owner.as_uuid(),
            WsEvent::KeyPackagesLow(KeyPackagesLowPayload {}),
        );
    }
}
