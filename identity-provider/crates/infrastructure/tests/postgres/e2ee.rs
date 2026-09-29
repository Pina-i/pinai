use domain::e2ee::testing::contract;
use infrastructure::postgres::{
    PgCommitLog, PgDevices, PgHistoryArchive, PgKeyPackages, PgWelcomes,
};
use sqlx::PgPool;

use super::{a_user, an_account};

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_registered_device_is_found_and_listed_with_its_attestation(pool: PgPool) {
    let alice = a_user(&pool).await;
    contract::a_registered_device_is_found_and_listed_with_its_attestation(
        &PgDevices::new(pool),
        alice,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn registering_again_replaces_the_attestation_and_keeps_the_label(pool: PgPool) {
    let alice = a_user(&pool).await;
    contract::registering_again_replaces_the_attestation_and_keeps_the_label(
        &PgDevices::new(pool),
        alice,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn devices_are_listed_active_first_then_most_recently_seen(pool: PgPool) {
    let (alice, bob) = (a_user(&pool).await, a_user(&pool).await);
    contract::devices_are_listed_active_first_then_most_recently_seen(
        &PgDevices::new(pool.clone()),
        &PgKeyPackages::new(pool),
        alice,
        bob,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_device_is_revoked_once_and_only_by_its_owner(pool: PgPool) {
    let (alice, bob) = (a_user(&pool).await, a_user(&pool).await);
    contract::a_device_is_revoked_once_and_only_by_its_owner(&PgDevices::new(pool), alice, bob)
        .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_stash_counts_per_device_what_is_neither_claimed_nor_expired(pool: PgPool) {
    let (alice, bob) = (a_user(&pool).await, a_user(&pool).await);
    contract::a_stash_counts_per_device_what_is_neither_claimed_nor_expired(
        &PgKeyPackages::new(pool),
        alice,
        bob,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn stashing_records_a_new_device_and_marks_a_known_one_seen(pool: PgPool) {
    let alice = a_user(&pool).await;
    contract::stashing_records_a_new_device_and_marks_a_known_one_seen(
        &PgDevices::new(pool.clone()),
        &PgKeyPackages::new(pool),
        alice,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_claim_hands_out_the_oldest_package_once(pool: PgPool) {
    let alice = a_user(&pool).await;
    contract::a_claim_hands_out_the_oldest_package_once(&PgKeyPackages::new(pool), alice).await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_claim_for_any_device_names_the_one_it_took_from(pool: PgPool) {
    let (alice, bob) = (a_user(&pool).await, a_user(&pool).await);
    contract::a_claim_for_any_device_names_the_one_it_took_from(
        &PgKeyPackages::new(pool),
        alice,
        bob,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn spent_packages_are_deleted_once_expired_or_claimed_past_the_cutoff(pool: PgPool) {
    let alice = a_user(&pool).await;
    contract::spent_packages_are_deleted_once_expired_or_claimed_past_the_cutoff(
        &PgKeyPackages::new(pool),
        alice,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_claim_never_hands_out_a_revoked_devices_packages(pool: PgPool) {
    let alice = a_user(&pool).await;
    contract::a_claim_never_hands_out_a_revoked_devices_packages(
        &PgDevices::new(pool.clone()),
        &PgKeyPackages::new(pool),
        alice,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_device_of_another_account_is_neither_attested_nor_stashed_for(pool: PgPool) {
    let (alice, bob) = (a_user(&pool).await, a_user(&pool).await);
    contract::a_device_of_another_account_is_neither_attested_nor_stashed_for(
        &PgDevices::new(pool.clone()),
        &PgKeyPackages::new(pool),
        alice,
        bob,
    )
    .await;
}

/// A conversation row, for the tables that reference one.
async fn a_conversation(pool: &PgPool) -> domain::ConversationId {
    let id = domain::ConversationId::generate();
    sqlx::query("INSERT INTO conversations (id, kind) VALUES ($1, 'group')")
        .bind(id.as_uuid())
        .execute(pool)
        .await
        .expect("seed a conversation");
    id
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn commits_are_caught_up_in_epoch_order_after_an_epoch(pool: PgPool) {
    let (group, other) = (a_conversation(&pool).await, a_conversation(&pool).await);
    let alice = an_account(&pool, "alice").await;
    contract::commits_are_caught_up_in_epoch_order_after_an_epoch(
        &PgCommitLog::new(pool),
        group,
        other,
        &alice.actor_uri,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_commit_at_a_taken_epoch_loses_to_the_one_there(pool: PgPool) {
    let group = a_conversation(&pool).await;
    let (alice, bob) = (
        an_account(&pool, "alice").await,
        an_account(&pool, "bob").await,
    );
    contract::a_commit_at_a_taken_epoch_loses_to_the_one_there(
        &PgCommitLog::new(pool),
        group,
        &alice.actor_uri,
        &bob.actor_uri,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_welcome_is_claimed_once_and_only_by_its_device(pool: PgPool) {
    let (alice, bob) = (a_user(&pool).await, a_user(&pool).await);
    contract::a_welcome_is_claimed_once_and_only_by_its_device(&PgWelcomes::new(pool), alice, bob)
        .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn claimed_welcomes_are_deleted_once_past_the_cutoff(pool: PgPool) {
    let alice = a_user(&pool).await;
    contract::claimed_welcomes_are_deleted_once_past_the_cutoff(&PgWelcomes::new(pool), alice)
        .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn an_entry_is_archived_once_per_owner(pool: PgPool) {
    let (alice, bob) = (a_user(&pool).await, a_user(&pool).await);
    let conversation = a_conversation(&pool).await;
    contract::an_entry_is_archived_once_per_owner(
        &PgHistoryArchive::new(pool),
        alice,
        bob,
        conversation,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn the_archive_pages_newest_first_before_a_cursor(pool: PgPool) {
    let alice = a_user(&pool).await;
    let conversation = a_conversation(&pool).await;
    contract::the_archive_pages_newest_first_before_a_cursor(
        &PgHistoryArchive::new(pool),
        alice,
        conversation,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn clearing_an_archive_deletes_its_owners_entries_only(pool: PgPool) {
    let (alice, bob) = (a_user(&pool).await, a_user(&pool).await);
    let conversation = a_conversation(&pool).await;
    contract::clearing_an_archive_deletes_its_owners_entries_only(
        &PgHistoryArchive::new(pool),
        alice,
        bob,
        conversation,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn the_first_salt_set_is_kept(pool: PgPool) {
    let alice = a_user(&pool).await;
    contract::the_first_salt_set_is_kept(&PgHistoryArchive::new(pool), alice).await;
}
