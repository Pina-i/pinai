use std::sync::Arc;

use super::*;

#[tokio::test]
async fn a_client_is_found_by_its_id() {
    let clients = InMemoryClients::default();
    contract::a_client_is_found_by_its_id(&clients, &clients).await;
}

#[tokio::test]
async fn every_client_is_listed() {
    let clients = InMemoryClients::default();
    contract::every_client_is_listed(&clients, &clients).await;
}

#[tokio::test]
async fn an_account_is_found_by_email_and_id_with_its_sign_in_state() {
    let accounts = InMemorySignInAccounts::default();
    contract::an_account_is_found_by_email_and_id_with_its_sign_in_state(&accounts, &accounts)
        .await;
}

#[tokio::test]
async fn a_code_is_good_once_and_only_until_it_expires() {
    contract::a_code_is_good_once_and_only_until_it_expires(
        &InMemoryCodes::default(),
        UserId::generate(),
    )
    .await;
}

#[tokio::test]
async fn a_new_account_is_unconfirmed_and_found_by_its_email() {
    let accounts = InMemorySignInAccounts::default();
    contract::a_new_account_is_unconfirmed_and_found_by_its_email(&accounts, &accounts).await;
}

#[tokio::test]
async fn accounts_left_unconfirmed_are_deleted_after_their_grace() {
    let accounts = InMemorySignInAccounts::default();
    contract::accounts_left_unconfirmed_are_deleted_after_their_grace(
        &accounts, &accounts, &accounts,
    )
    .await;
}

/// Codes over an account still to confirm.
async fn codes_for_bob() -> (Arc<InMemorySignInAccounts>, InMemorySignupCodes, UserId) {
    let accounts = Arc::new(InMemorySignInAccounts::default());
    let bob = contract::a_new_account("bob");
    accounts.create(&bob).await.unwrap();
    let codes = InMemorySignupCodes::confirming(accounts.clone());
    (accounts, codes, bob.id)
}

#[tokio::test]
async fn a_signup_code_confirms_its_account_once() {
    let (accounts, codes, bob) = codes_for_bob().await;
    contract::a_signup_code_confirms_its_account_once(&codes, &*accounts, bob).await;
}

#[tokio::test]
async fn wrong_codes_count_down_to_exhaustion() {
    let (_, codes, bob) = codes_for_bob().await;
    contract::wrong_codes_count_down_to_exhaustion(&codes, bob).await;
}

#[tokio::test]
async fn only_the_latest_live_code_counts() {
    let (_, codes, bob) = codes_for_bob().await;
    contract::only_the_latest_live_code_counts(&codes, bob).await;
}

#[tokio::test]
async fn the_codes_issued_lately_are_counted() {
    let (_, codes, bob) = codes_for_bob().await;
    contract::the_codes_issued_lately_are_counted(&codes, bob).await;
}

#[tokio::test]
async fn spent_codes_are_deleted_and_the_live_one_kept() {
    let (_, codes, bob) = codes_for_bob().await;
    contract::spent_codes_are_deleted_and_the_live_one_kept(&codes, bob).await;
}

#[tokio::test]
async fn an_address_or_a_handle_is_one_accounts_whatever_its_case() {
    let accounts = InMemorySignInAccounts::default();
    contract::an_address_or_a_handle_is_one_accounts_whatever_its_case(
        &accounts, &accounts, &accounts,
    )
    .await;
}

/// Second factors over an account signed up without one.
async fn factors_for_bob() -> (Arc<InMemorySignInAccounts>, InMemorySecondFactors, UserId) {
    let bob = signed_up("bob");
    let accounts = Arc::new(InMemorySignInAccounts::with([bob.clone()]));
    let factors = InMemorySecondFactors::for_accounts(accounts.clone());
    (accounts, factors, bob.id)
}

#[tokio::test]
async fn an_enrollment_waits_until_the_second_factor_is_turned_on() {
    let (_, factors, bob) = factors_for_bob().await;
    contract::an_enrollment_waits_until_the_second_factor_is_turned_on(&factors, bob).await;
}

#[tokio::test]
async fn turning_the_second_factor_on_mints_its_codes_and_off_forgets_everything() {
    let (accounts, factors, bob) = factors_for_bob().await;
    contract::turning_the_second_factor_on_mints_its_codes_and_off_forgets_everything(
        &factors, &*accounts, bob,
    )
    .await;
}

#[tokio::test]
async fn a_recovery_code_is_used_once_and_a_new_set_replaces_the_old() {
    let (_, factors, bob) = factors_for_bob().await;
    contract::a_recovery_code_is_used_once_and_a_new_set_replaces_the_old(&factors, bob).await;
}

#[tokio::test]
async fn an_open_ticket_is_found_until_spent_or_expired() {
    contract::an_open_ticket_is_found_until_spent_or_expired(
        &RecordingTickets::default(),
        UserId::generate(),
    )
    .await;
}

#[tokio::test]
async fn a_time_step_is_used_once_and_only_forward() {
    let (_, factors, bob) = factors_for_bob().await;
    contract::a_time_step_is_used_once_and_only_forward(&factors, bob).await;
}

#[tokio::test]
async fn a_ticket_gives_five_attempts_until_spent_or_expired() {
    contract::a_ticket_gives_five_attempts_until_spent_or_expired(
        &RecordingTickets::default(),
        UserId::generate(),
    )
    .await;
}
