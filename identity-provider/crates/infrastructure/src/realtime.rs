//! Adapters over the legacy WebSocket hub (`idp-realtime`), until realtime migrates.

mod devices;
mod groups;
mod messaging;
mod mls;
mod presence;
mod profile;
mod settings;
mod social;

pub use devices::HubDeviceNotifier;
pub use groups::HubGroupNotifier;
pub use messaging::HubMessageNotifier;
pub use mls::HubMlsNotifier;
pub use presence::HubPresenceNotifier;
pub use profile::HubProfileNotifier;
pub use settings::HubSettingsNotifier;
pub use social::HubSocialNotifier;
