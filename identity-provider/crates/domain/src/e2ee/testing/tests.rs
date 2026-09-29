use super::*;

fn store() -> InMemoryKeyDirectory {
    InMemoryKeyDirectory::default()
}

#[tokio::test]
async fn a_registered_device_is_found_and_listed_with_its_attestation() {
    contract::a_registered_device_is_found_and_listed_with_its_attestation(
        &store(),
        UserId::generate(),
    )
    .await;
}

#[tokio::test]
async fn registering_again_replaces_the_attestation_and_keeps_the_label() {
    contract::registering_again_replaces_the_attestation_and_keeps_the_label(
        &store(),
        UserId::generate(),
    )
    .await;
}

#[tokio::test]
async fn devices_are_listed_active_first_then_most_recently_seen() {
    let store = store();
    contract::devices_are_listed_active_first_then_most_recently_seen(
        &store,
        &store,
        UserId::generate(),
        UserId::generate(),
    )
    .await;
}

#[tokio::test]
async fn a_device_is_revoked_once_and_only_by_its_owner() {
    contract::a_device_is_revoked_once_and_only_by_its_owner(
        &store(),
        UserId::generate(),
        UserId::generate(),
    )
    .await;
}

#[tokio::test]
async fn a_stash_counts_per_device_what_is_neither_claimed_nor_expired() {
    contract::a_stash_counts_per_device_what_is_neither_claimed_nor_expired(
        &store(),
        UserId::generate(),
        UserId::generate(),
    )
    .await;
}

#[tokio::test]
async fn stashing_records_a_new_device_and_marks_a_known_one_seen() {
    let store = store();
    contract::stashing_records_a_new_device_and_marks_a_known_one_seen(
        &store,
        &store,
        UserId::generate(),
    )
    .await;
}

#[tokio::test]
async fn a_claim_hands_out_the_oldest_package_once() {
    contract::a_claim_hands_out_the_oldest_package_once(&store(), UserId::generate()).await;
}

#[tokio::test]
async fn a_claim_for_any_device_names_the_one_it_took_from() {
    contract::a_claim_for_any_device_names_the_one_it_took_from(
        &store(),
        UserId::generate(),
        UserId::generate(),
    )
    .await;
}

#[tokio::test]
async fn spent_packages_are_deleted_once_expired_or_claimed_past_the_cutoff() {
    contract::spent_packages_are_deleted_once_expired_or_claimed_past_the_cutoff(
        &store(),
        UserId::generate(),
    )
    .await;
}

#[tokio::test]
async fn a_claim_never_hands_out_a_revoked_devices_packages() {
    let store = store();
    contract::a_claim_never_hands_out_a_revoked_devices_packages(
        &store,
        &store,
        UserId::generate(),
    )
    .await;
}

#[tokio::test]
async fn a_device_of_another_account_is_neither_attested_nor_stashed_for() {
    let store = store();
    contract::a_device_of_another_account_is_neither_attested_nor_stashed_for(
        &store,
        &store,
        UserId::generate(),
        UserId::generate(),
    )
    .await;
}

#[tokio::test]
async fn commits_are_caught_up_in_epoch_order_after_an_epoch() {
    contract::commits_are_caught_up_in_epoch_order_after_an_epoch(
        &InMemoryDelivery::default(),
        ConversationId::generate(),
        ConversationId::generate(),
        &crate::identity::testing::account("alice").actor_uri,
    )
    .await;
}

#[tokio::test]
async fn a_commit_at_a_taken_epoch_loses_to_the_one_there() {
    contract::a_commit_at_a_taken_epoch_loses_to_the_one_there(
        &InMemoryDelivery::default(),
        ConversationId::generate(),
        &crate::identity::testing::account("alice").actor_uri,
        &crate::identity::testing::account("bob").actor_uri,
    )
    .await;
}

#[tokio::test]
async fn a_welcome_is_claimed_once_and_only_by_its_device() {
    contract::a_welcome_is_claimed_once_and_only_by_its_device(
        &InMemoryDelivery::default(),
        UserId::generate(),
        UserId::generate(),
    )
    .await;
}

#[tokio::test]
async fn claimed_welcomes_are_deleted_once_past_the_cutoff() {
    contract::claimed_welcomes_are_deleted_once_past_the_cutoff(
        &InMemoryDelivery::default(),
        UserId::generate(),
    )
    .await;
}

#[tokio::test]
async fn an_entry_is_archived_once_per_owner() {
    contract::an_entry_is_archived_once_per_owner(
        &InMemoryArchive::default(),
        UserId::generate(),
        UserId::generate(),
        ConversationId::generate(),
    )
    .await;
}

#[tokio::test]
async fn the_archive_pages_newest_first_before_a_cursor() {
    contract::the_archive_pages_newest_first_before_a_cursor(
        &InMemoryArchive::default(),
        UserId::generate(),
        ConversationId::generate(),
    )
    .await;
}

#[tokio::test]
async fn clearing_an_archive_deletes_its_owners_entries_only() {
    contract::clearing_an_archive_deletes_its_owners_entries_only(
        &InMemoryArchive::default(),
        UserId::generate(),
        UserId::generate(),
        ConversationId::generate(),
    )
    .await;
}

#[tokio::test]
async fn the_first_salt_set_is_kept() {
    contract::the_first_salt_set_is_kept(&InMemoryArchive::default(), UserId::generate()).await;
}
