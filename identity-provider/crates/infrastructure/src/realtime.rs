//! Pushes to the accounts' live connections: each event written as its frame — the JSON clients
//! read, `events` — onto the connections hub.

mod devices;
mod events;
mod groups;
mod messaging;
mod mls;
mod presence;
mod profile;
mod settings;
mod social;

use connections::{Frame, Hub};
use uuid::Uuid;

pub use devices::HubDeviceNotifier;
pub use groups::HubGroupNotifier;
pub use messaging::HubMessageNotifier;
pub use mls::HubMlsNotifier;
pub use presence::HubPresenceNotifier;
pub use profile::HubProfileNotifier;
pub use settings::HubSettingsNotifier;
pub use social::HubSocialNotifier;

fn frame(event: &events::WsEvent) -> Frame {
    Frame::from(serde_json::to_string(event).expect("an event is plain JSON"))
}

/// `event` to every live connection of `to`.
fn push(hub: &Hub, to: &Uuid, event: events::WsEvent) {
    hub.send_to_user(to, frame(&event));
}
