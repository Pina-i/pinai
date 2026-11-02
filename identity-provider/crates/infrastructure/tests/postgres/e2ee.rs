use domain::e2ee::testing::contract;
use domain::e2ee::{
    ApprovalPublicKey, ArchiveNonce, Archived, HistoryArchive, HistoryCheckValue,
    HistoryGeneration, HistoryKey, HistoryKeys, HistorySalt, KeyReplace, NewArchiveEntry,
};
use infrastructure::postgres::{
    PgCommitLog, PgDevices, PgHistoryArchive, PgHistoryKeys, PgKeyPackages, PgWelcomes,
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
async fn a_device_records_the_current_history_generation_while_unrevoked(pool: PgPool) {
    let (alice, bob) = (a_user(&pool).await, a_user(&pool).await);
    contract::a_device_records_the_current_history_generation_while_unrevoked(
        &PgDevices::new(pool.clone()),
        &PgHistoryKeys::new(pool),
        alice,
        bob,
    )
    .await;
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
async fn a_known_device_takes_a_stashs_label_only_when_asked(pool: PgPool) {
    let alice = a_user(&pool).await;
    contract::a_known_device_takes_a_stashs_label_only_when_asked(
        &PgDevices::new(pool.clone()),
        &PgKeyPackages::new(pool),
        alice,
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

/// The archive, its keys and the devices that set them, over one database.
fn history(pool: &PgPool) -> (PgHistoryArchive, PgHistoryKeys, PgDevices) {
    (
        PgHistoryArchive::new(pool.clone()),
        PgHistoryKeys::new(pool.clone()),
        PgDevices::new(pool.clone()),
    )
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn an_entry_is_archived_once_per_owner(pool: PgPool) {
    let (alice, bob) = (a_user(&pool).await, a_user(&pool).await);
    let conversation = a_conversation(&pool).await;
    let (archive, keys, devices) = history(&pool);
    contract::an_entry_is_archived_once_per_owner(
        &archive,
        &keys,
        &devices,
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
    let (archive, keys, devices) = history(&pool);
    contract::the_archive_pages_newest_first_before_a_cursor(
        &archive,
        &keys,
        &devices,
        alice,
        conversation,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn clearing_an_archive_deletes_its_owners_entries_and_keeps_the_key(pool: PgPool) {
    let (alice, bob) = (a_user(&pool).await, a_user(&pool).await);
    let conversation = a_conversation(&pool).await;
    let (archive, keys, devices) = history(&pool);
    contract::clearing_an_archive_deletes_its_owners_entries_and_keeps_the_key(
        &archive,
        &keys,
        &devices,
        alice,
        bob,
        conversation,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn an_upload_is_stored_only_under_the_current_generation(pool: PgPool) {
    let alice = a_user(&pool).await;
    let conversation = a_conversation(&pool).await;
    let (archive, keys, devices) = history(&pool);
    contract::an_upload_is_stored_only_under_the_current_generation(
        &archive,
        &keys,
        &devices,
        alice,
        conversation,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_key_is_set_only_for_the_generation_after_the_current_one(pool: PgPool) {
    let (alice, bob) = (a_user(&pool).await, a_user(&pool).await);
    let (_, keys, devices) = history(&pool);
    contract::a_key_is_set_only_for_the_generation_after_the_current_one(
        &keys, &devices, alice, bob,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn setting_the_key_held_again_is_a_retry_that_writes_nothing(pool: PgPool) {
    let alice = a_user(&pool).await;
    let conversation = a_conversation(&pool).await;
    let (archive, keys, devices) = history(&pool);
    contract::setting_the_key_held_again_is_a_retry_that_writes_nothing(
        &archive,
        &keys,
        &devices,
        alice,
        conversation,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_new_generation_erases_its_owners_archive_in_the_same_write(pool: PgPool) {
    let (alice, bob) = (a_user(&pool).await, a_user(&pool).await);
    let conversation = a_conversation(&pool).await;
    let (archive, keys, devices) = history(&pool);
    contract::a_new_generation_erases_its_owners_archive_in_the_same_write(
        &archive,
        &keys,
        &devices,
        alice,
        bob,
        conversation,
    )
    .await;
}

fn history_key(generation: i64, byte: u8) -> HistoryKey {
    HistoryKey {
        generation: HistoryGeneration::parse(generation).unwrap(),
        salt: HistorySalt::parse(&[byte; 16]).unwrap(),
        check_value: HistoryCheckValue::parse(&[byte; 32]).unwrap(),
        approval_public_key: ApprovalPublicKey::parse(&[byte; 32]).unwrap(),
    }
}

/// A device row of `owner`'s, which a history key may name as having set it.
async fn a_device(pool: &PgPool, owner: domain::UserId) -> domain::DeviceId {
    let id = domain::DeviceId::generate();
    sqlx::query(
        "INSERT INTO user_devices (device_id, user_id, display_name, kind) \
         VALUES ($1, $2, 'laptop', 'laptop')",
    )
    .bind(id.as_uuid())
    .bind(owner.as_uuid())
    .execute(pool)
    .await
    .expect("seed a device");
    id
}

fn entry(conversation: domain::ConversationId) -> NewArchiveEntry {
    NewArchiveEntry {
        id: domain::MessageId::generate(),
        conversation,
        ciphertext: vec![1; 16],
        nonce: ArchiveNonce::parse(&[1; 12]).unwrap(),
        client_message_id: None,
    }
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn two_devices_setting_the_same_generation_at_once_make_one(pool: PgPool) {
    let keys = PgHistoryKeys::new(pool.clone());

    for generation in 1..=10 {
        let alice = a_user(&pool).await;
        let (laptop, phone) = (a_device(&pool, alice).await, a_device(&pool, alice).await);
        for earlier in 1..generation {
            keys.replace(alice, &history_key(earlier, 0), laptop)
                .await
                .unwrap();
        }
        let (one, other) = (history_key(generation, 1), history_key(generation, 2));

        let (first, second) = tokio::join!(
            keys.replace(alice, &one, laptop),
            keys.replace(alice, &other, phone),
        );

        let mut outcomes = [first.unwrap(), second.unwrap()];
        outcomes.sort_by_key(|outcome| matches!(outcome, KeyReplace::Conflict(_)));
        let made = HistoryGeneration::parse(generation).unwrap();
        assert_eq!(
            outcomes,
            [
                KeyReplace::Replaced { erased: 0 },
                KeyReplace::Conflict(Some(made))
            ]
        );
        let held = keys.current(alice).await.unwrap().unwrap();
        assert_eq!(held.key.generation, made);
    }
}

/// Whichever commits first, no entry of the replaced generation survives the new one.
#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn an_upload_racing_a_new_generation_is_erased_or_refused(pool: PgPool) {
    let (archive, keys) = (
        PgHistoryArchive::new(pool.clone()),
        PgHistoryKeys::new(pool.clone()),
    );
    let conversation = a_conversation(&pool).await;
    let first = HistoryGeneration::FIRST;

    for _ in 0..20 {
        let alice = a_user(&pool).await;
        let device = a_device(&pool, alice).await;
        keys.replace(alice, &history_key(1, 1), device)
            .await
            .unwrap();
        let batch: Vec<_> = (0..20).map(|_| entry(conversation)).collect();
        let next = history_key(2, 2);

        let (uploaded, replaced) = tokio::join!(
            archive.store(alice, first, &batch),
            keys.replace(alice, &next, device),
        );

        let erased = match replaced.unwrap() {
            KeyReplace::Replaced { erased } => erased,
            other => panic!("{other:?}"),
        };
        match uploaded.unwrap() {
            Archived::Stored(stored) => assert_eq!(erased, stored, "stored, then erased"),
            Archived::Stale => assert_eq!(erased, 0, "refused"),
        }
        assert!(archive.page(alice, None, 50).await.unwrap().is_empty());
    }
}

/// Two devices archiving the same messages at once, listed in opposite orders.
#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn two_uploads_of_the_same_entries_at_once_never_deadlock(pool: PgPool) {
    let (archive, keys) = (
        PgHistoryArchive::new(pool.clone()),
        PgHistoryKeys::new(pool.clone()),
    );
    let conversation = a_conversation(&pool).await;

    for _ in 0..10 {
        let alice = a_user(&pool).await;
        let device = a_device(&pool, alice).await;
        keys.replace(alice, &history_key(1, 1), device)
            .await
            .unwrap();
        let batch: Vec<_> = (0..50).map(|_| entry(conversation)).collect();
        let reversed: Vec<_> = batch.iter().rev().cloned().collect();

        let (one, other) = tokio::join!(
            archive.store(alice, HistoryGeneration::FIRST, &batch),
            archive.store(alice, HistoryGeneration::FIRST, &reversed),
        );

        let stored = |uploaded: Result<Archived, _>| match uploaded {
            Ok(Archived::Stored(new)) => new,
            other => panic!("{other:?}"),
        };
        assert_eq!(stored(one) + stored(other), 50, "each entry once");
    }
}
