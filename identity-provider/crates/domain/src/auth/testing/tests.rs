use std::sync::Arc;

use super::*;

#[tokio::test]
async fn a_published_client_is_found_by_its_url() {
    let clients = InMemoryClients::default();
    contract::a_published_client_is_found_by_its_url(&clients, &clients).await;
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
        SessionId::generate(),
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

#[tokio::test]
async fn an_app_signed_in_to_is_remembered_and_staying_signed_in_kept() {
    contract::an_app_signed_in_to_is_remembered_and_staying_signed_in_kept(
        &InMemoryClientSignIns::default(),
        UserId::generate(),
        UserId::generate(),
    )
    .await;
}

#[tokio::test]
async fn a_session_opens_is_used_and_ends_once() {
    contract::a_session_opens_is_used_and_ends_once(
        &InMemorySessions::default(),
        UserId::generate(),
    )
    .await;
}

#[tokio::test]
async fn sessions_ended_are_swept_after_their_retention() {
    contract::sessions_ended_are_swept_after_their_retention(
        &InMemorySessions::default(),
        UserId::generate(),
    )
    .await;
}

#[tokio::test]
async fn a_refresh_token_rotates_at_each_use_and_a_used_one_is_reused() {
    contract::a_refresh_token_rotates_at_each_use_and_a_used_one_is_reused(
        &InMemoryRefreshTokens::default(),
        SessionId::generate(),
    )
    .await;
}

#[tokio::test]
async fn a_lost_answer_is_answered_again_within_the_grace() {
    contract::a_lost_answer_is_answered_again_within_the_grace(
        &InMemoryRefreshTokens::default(),
        SessionId::generate(),
    )
    .await;
}

#[tokio::test]
async fn refresh_tokens_unused_since_the_cutoff_are_swept() {
    contract::refresh_tokens_unused_since_the_cutoff_are_swept(
        &InMemoryRefreshTokens::default(),
        SessionId::generate(),
    )
    .await;
}

#[tokio::test]
async fn a_device_holds_one_session_the_latest_linked() {
    contract::a_device_holds_one_session_the_latest_linked(
        &InMemorySessions::default(),
        UserId::generate(),
        DeviceId::generate(),
    )
    .await;
}

#[tokio::test]
async fn a_revoked_device_and_signing_out_elsewhere_end_the_right_sessions() {
    contract::a_revoked_device_and_signing_out_elsewhere_end_the_right_sessions(
        &InMemorySessions::default(),
        UserId::generate(),
        UserId::generate(),
        DeviceId::generate(),
    )
    .await;
}

#[tokio::test]
async fn a_refresh_token_names_its_session_to_its_own_client_only() {
    contract::a_refresh_token_names_its_session_to_its_own_client_only(
        &InMemoryRefreshTokens::default(),
        SessionId::generate(),
    )
    .await;
}

#[tokio::test]
async fn an_admitted_account_is_never_swept_as_unconfirmed() {
    let accounts = InMemorySignInAccounts::default();
    contract::an_admitted_account_is_never_swept_as_unconfirmed(&accounts, &accounts, &accounts)
        .await;
}

#[tokio::test]
async fn the_admin_is_created_admitted_unconfirmed_and_never_written_over() {
    let accounts = InMemorySignInAccounts::default();
    contract::the_admin_is_created_admitted_unconfirmed_and_never_written_over(
        &accounts, &accounts,
    )
    .await;
}

#[tokio::test]
async fn the_admin_facts_tell_who_has_an_address_and_whether_any_admin_exists() {
    let accounts = InMemorySignInAccounts::default();
    contract::the_admin_facts_tell_who_has_an_address_and_whether_any_admin_exists(
        &accounts, &accounts,
    )
    .await;
}
