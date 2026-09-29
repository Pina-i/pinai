use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use domain::e2ee::{DeviceNotifier, DeviceRootKey};
use domain::identity::ActorUri;
use domain::{DeviceId, UserId};
use idp_realtime::{DeviceJoinedPayload, WsEvent, WsHub};

/// Tells the owner's live sessions, which add the new device to their groups; an offline
/// device reconciles from the device list when it connects.
pub struct HubDeviceNotifier {
    hub: Arc<WsHub>,
}

impl HubDeviceNotifier {
    pub fn new(hub: Arc<WsHub>) -> Self {
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
        self.hub.send_to_user(
            &owner.as_uuid(),
            WsEvent::DeviceJoined(DeviceJoinedPayload {
                actor_uri: actor.to_string(),
                device_id: device.as_uuid(),
                drk_public_key: B64.encode(key.as_bytes()),
            }),
        );
    }
}
