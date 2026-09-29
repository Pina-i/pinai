//! In-memory fakes of the settings ports and the contract every `SettingsStore` must satisfy.

use std::collections::HashMap;
use std::sync::Mutex;

use serde_json::{Map, Value};

use crate::UserId;

use super::{SettingsDocument, SettingsNotifier, SettingsPatch, SettingsStore, SettingsStoreError};

#[derive(Default)]
pub struct InMemorySettingsStore {
    documents: Mutex<HashMap<UserId, Map<String, Value>>>,
}

#[async_trait::async_trait]
impl SettingsStore for InMemorySettingsStore {
    async fn load(&self, user: UserId) -> Result<Option<SettingsDocument>, SettingsStoreError> {
        let documents = self.documents.lock().unwrap();
        Ok(documents
            .get(&user)
            .map(|document| SettingsDocument::from_value(Value::Object(document.clone()))))
    }

    async fn merge(
        &self,
        user: UserId,
        patch: &SettingsPatch,
    ) -> Result<SettingsDocument, SettingsStoreError> {
        let mut documents = self.documents.lock().unwrap();
        let mut merged = documents.get(&user).cloned().unwrap_or_default();
        if let Value::Object(sections) = patch.as_value() {
            for (name, section) in sections {
                merged.insert(name.clone(), section.clone());
            }
        }
        if Value::Object(merged.clone()).to_string().len() > SettingsDocument::MAX_BYTES {
            return Err(SettingsStoreError::TooLarge);
        }
        documents.insert(user, merged.clone());
        Ok(SettingsDocument::from_value(Value::Object(merged)))
    }
}

/// Records every notification, in order.
#[derive(Default)]
pub struct RecordingSettingsNotifier {
    notified: Mutex<Vec<(UserId, SettingsDocument)>>,
}

impl RecordingSettingsNotifier {
    pub fn notified(&self) -> Vec<(UserId, SettingsDocument)> {
        self.notified.lock().unwrap().clone()
    }
}

impl SettingsNotifier for RecordingSettingsNotifier {
    fn settings_updated(&self, user: UserId, settings: &SettingsDocument) {
        self.notified.lock().unwrap().push((user, settings.clone()));
    }
}

/// Run against the in-memory fake and against the Postgres adapter, so the two cannot drift.
/// Each check takes a user the store accepts — the Postgres one needs a real `users` row.
pub mod contract {
    use serde_json::json;

    use crate::UserId;
    use crate::settings::{SettingsPatch, SettingsStore, SettingsStoreError};

    fn patch(change: serde_json::Value) -> SettingsPatch {
        SettingsPatch::parse(change).expect("a valid change")
    }

    pub async fn an_account_that_never_saved_settings_has_no_document(
        store: &dyn SettingsStore,
        user: UserId,
    ) {
        assert_eq!(store.load(user).await.unwrap(), None);
    }

    pub async fn a_document_grown_past_16_kib_is_refused(store: &dyn SettingsStore, user: UserId) {
        let oversized = patch(json!({ "notes": { "text": "x".repeat(20 * 1024) } }));

        let refused = store.merge(user, &oversized).await;

        assert!(
            matches!(refused, Err(SettingsStoreError::TooLarge)),
            "{refused:?}"
        );
    }

    pub async fn a_merge_replaces_the_sections_it_names_and_keeps_the_others(
        store: &dyn SettingsStore,
        user: UserId,
    ) {
        store
            .merge(
                user,
                &patch(json!({
                    "appearance": { "family": "lagoon", "motif": "raranga" },
                    "notifications": { "muteAll": false }
                })),
            )
            .await
            .unwrap();

        let merged = store
            .merge(user, &patch(json!({ "appearance": { "family": "sand" } })))
            .await
            .unwrap();

        assert_eq!(
            merged.as_value(),
            &json!({
                "appearance": { "family": "sand" },
                "notifications": { "muteAll": false }
            })
        );
    }
}

#[cfg(test)]
mod tests;
