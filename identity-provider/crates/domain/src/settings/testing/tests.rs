use super::*;
use crate::UserId;

#[tokio::test]
async fn a_merge_replaces_the_sections_it_names_and_keeps_the_others() {
    contract::a_merge_replaces_the_sections_it_names_and_keeps_the_others(
        &InMemorySettingsStore::default(),
        UserId::generate(),
    )
    .await;
}

#[tokio::test]
async fn an_account_that_never_saved_settings_has_no_document() {
    contract::an_account_that_never_saved_settings_has_no_document(
        &InMemorySettingsStore::default(),
        UserId::generate(),
    )
    .await;
}

#[tokio::test]
async fn a_document_grown_past_16_kib_is_refused() {
    contract::a_document_grown_past_16_kib_is_refused(
        &InMemorySettingsStore::default(),
        UserId::generate(),
    )
    .await;
}
