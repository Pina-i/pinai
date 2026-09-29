//! The account's settings: one JSON document owned by the client. Each top-level key is a
//! section, stored without being interpreted, so a client that doesn't know a section never
//! drops it.

mod document;
mod error;
mod patch;
mod ports;
#[cfg(any(test, feature = "test-utils"))]
pub mod testing;

pub use document::SettingsDocument;
pub use error::SettingsError;
pub use patch::SettingsPatch;
pub use ports::{SettingsNotifier, SettingsStore, SettingsStoreError};
