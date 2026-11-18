use super::*;

#[tokio::test]
async fn every_account_that_joined_counts() {
    let accounts = InMemoryAccounts::with([account("alice"), account("bob")]);
    accounts.signing_up(account("kai"));

    contract::every_account_that_joined_counts(&accounts).await;
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

#[tokio::test]
async fn a_sign_up_still_to_confirm_is_found_by_its_id_only() {
    let (alice, kai) = (account("alice"), account("kai"));
    let accounts = InMemoryAccounts::with([alice.clone()]);
    accounts.signing_up(kai.clone());

    contract::a_sign_up_still_to_confirm_is_found_by_its_id_only(&accounts, &[alice], &kai).await;
}
