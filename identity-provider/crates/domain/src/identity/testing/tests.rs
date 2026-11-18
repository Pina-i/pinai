use super::*;

#[tokio::test]
async fn every_account_counts() {
    contract::every_account_counts(&InMemoryAccounts::with([account("alice"), account("bob")]))
        .await;
}

#[tokio::test]
async fn nothing_is_saved_until_an_admin_saves() {
    contract::nothing_is_saved_until_an_admin_saves(&InMemorySavedIntro::default()).await;
}

#[tokio::test]
async fn the_last_text_saved_is_read_back() {
    contract::the_last_text_saved_is_read_back(&InMemorySavedIntro::default(), UserId::generate())
        .await;
}
