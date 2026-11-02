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
async fn a_device_holds_the_hpke_key_registered_with_its_attestation_until_replaced(pool: PgPool) {
    let alice = a_user(&pool).await;
    contract::a_device_holds_the_hpke_key_registered_with_its_attestation_until_replaced(
        &PgDevices::new(pool),
        alice,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_registration_decided_on_a_stale_read_writes_nothing(pool: PgPool) {
    let alice = a_user(&pool).await;
    contract::a_registration_decided_on_a_stale_read_writes_nothing(&PgDevices::new(pool), alice)
        .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_revoked_device_holds_no_hpke_key(pool: PgPool) {
    let alice = a_user(&pool).await;
    contract::a_revoked_device_holds_no_hpke_key(&PgDevices::new(pool), alice).await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn stashing_keeps_the_hpke_key_registered(pool: PgPool) {
    let alice = a_user(&pool).await;
    contract::stashing_keeps_the_hpke_key_registered(
        &PgDevices::new(pool.clone()),
        &PgKeyPackages::new(pool),
        alice,
    )
    .await;
}

/// Whoever writes the row: an HPKE key comes whole and signed by a root key, or not at all.
#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn the_table_takes_an_hpke_key_only_whole_and_with_a_root_key(pool: PgPool) {
    let alice = a_user(&pool).await;
    let insert = |drk: Option<Vec<u8>>, key: Option<Vec<u8>>, signature: Option<Vec<u8>>| {
        sqlx::query(
            "INSERT INTO user_devices \
                 (device_id, user_id, display_name, kind, drk_public_key, hpke_public_key, \
                  hpke_key_signature) \
             VALUES ($1, $2, 'laptop', 'laptop', $3, $4, $5)",
        )
        .bind(uuid::Uuid::new_v4())
        .bind(alice.as_uuid())
        .bind(drk)
        .bind(key)
        .bind(signature)
        .execute(&pool)
    };

    let whole = insert(Some(vec![1; 32]), Some(vec![2; 32]), Some(vec![3; 64])).await;
    let mut refused = Vec::new();
    for (drk, key, signature) in [
        (Some(vec![1; 32]), Some(vec![2; 32]), None),
        (Some(vec![1; 32]), None, Some(vec![3; 64])),
        (None, Some(vec![2; 32]), Some(vec![3; 64])),
    ] {
        let Err(sqlx::Error::Database(error)) = insert(drk, key, signature).await else {
            panic!("a broken HPKE key was stored");
        };
        refused.push(error.constraint().map(str::to_owned));
    }

    assert!(whole.is_ok(), "{whole:?}");
    assert_eq!(
        refused,
        vec![Some("user_devices_hpke_key_signed".to_owned()); 3]
    );
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
