use std::sync::Arc;

use domain::UserId;
use domain::settings::SettingsPatch;
use domain::settings::testing::{InMemorySettingsStore, RecordingSettingsNotifier};
use serde_json::json;

use super::*;

fn patch(change: serde_json::Value) -> SettingsPatch {
    SettingsPatch::parse(change).unwrap()
}

#[tokio::test]
async fn an_update_answers_with_the_merged_document() {
    let update = UpdateSettings::new(
        Arc::new(InMemorySettingsStore::default()),
        Arc::new(RecordingSettingsNotifier::default()),
    );
    let user = UserId::generate();
    update
        .execute(user, patch(json!({ "appearance": { "family": "lagoon" } })))
        .await
        .unwrap();

    let merged = update
        .execute(user, patch(json!({ "notifications": { "muteAll": true } })))
        .await
        .unwrap();

    assert_eq!(
        merged.as_value(),
        &json!({ "appearance": { "family": "lagoon" }, "notifications": { "muteAll": true } })
    );
}

#[tokio::test]
async fn the_users_sessions_receive_the_merged_document() {
    let notifier = Arc::new(RecordingSettingsNotifier::default());
    let update = UpdateSettings::new(Arc::new(InMemorySettingsStore::default()), notifier.clone());
    let user = UserId::generate();

    let merged = update
        .execute(user, patch(json!({ "appearance": { "family": "sand" } })))
        .await
        .unwrap();

    assert_eq!(notifier.notified(), vec![(user, merged)]);
}

#[tokio::test]
async fn a_change_that_would_grow_the_document_too_large_is_refused_unannounced() {
    let notifier = Arc::new(RecordingSettingsNotifier::default());
    let update = UpdateSettings::new(Arc::new(InMemorySettingsStore::default()), notifier.clone());

    let refused = update
        .execute(
            UserId::generate(),
            patch(json!({ "notes": { "text": "x".repeat(20 * 1024) } })),
        )
        .await;

    assert!(
        matches!(refused, Err(SettingsError::TooLarge)),
        "{refused:?}"
    );
    assert!(notifier.notified().is_empty());
}
