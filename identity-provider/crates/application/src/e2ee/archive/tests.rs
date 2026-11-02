use std::sync::Arc;

use domain::e2ee::testing::InMemoryArchive;
use domain::e2ee::{
    ApprovalPublicKey, ArchiveNonce, BatchSize, HistoryCheckValue, HistoryKey, HistorySalt,
    KeyReplace, StaleHistoryKey,
};
use domain::identity::Account;
use domain::identity::testing::{InMemoryAccounts, account};
use domain::messaging::testing::InMemoryMessaging;
use domain::messaging::{Member, Role};
use domain::{ConversationId, DeviceId, MessageId};

use super::*;

struct World {
    alice: Account,
    bob: Account,
    dm: ConversationId,
    left: ConversationId,
    elsewhere: ConversationId,
    archive: Arc<InMemoryArchive>,
    store: ArchiveMessages,
    read: ReadArchive,
    clear: ClearArchive,
}

fn generation(raw: i64) -> HistoryGeneration {
    HistoryGeneration::parse(raw).unwrap()
}

fn history_key(raw: i64) -> HistoryKey {
    HistoryKey {
        generation: generation(raw),
        salt: HistorySalt::parse(&[1; 16]).unwrap(),
        check_value: HistoryCheckValue::parse(&[2; 32]).unwrap(),
        approval_public_key: ApprovalPublicKey::parse(&[3; 32]).unwrap(),
    }
}

async fn world() -> World {
    let (alice, bob, carol) = (account("alice"), account("bob"), account("carol"));
    let conversations = Arc::new(InMemoryMessaging::default());
    let dm = conversations
        .open_dm(&alice.actor_uri, &bob.actor_uri, None)
        .await
        .unwrap();
    let member = |a: &Account, role| Member {
        actor_uri: a.actor_uri.clone(),
        role,
    };
    let left = conversations
        .create_group(
            None,
            &[member(&carol, Role::Admin), member(&alice, Role::Member)],
        )
        .await
        .unwrap()
        .id;
    conversations
        .remove_member(left, &alice.actor_uri, None, None)
        .await
        .unwrap();
    let elsewhere = conversations
        .open_dm(&bob.actor_uri, &carol.actor_uri, None)
        .await
        .unwrap();
    let archive = Arc::new(InMemoryArchive::default());
    for owner in [alice.id, bob.id] {
        archive
            .replace(owner, &history_key(1), DeviceId::generate())
            .await
            .unwrap();
    }
    World {
        store: ArchiveMessages::new(
            Arc::new(InMemoryAccounts::with([alice.clone(), bob.clone(), carol])),
            conversations,
            archive.clone(),
            archive.clone(),
        ),
        read: ReadArchive::new(archive.clone()),
        clear: ClearArchive::new(archive.clone()),
        alice,
        bob,
        dm,
        left,
        elsewhere,
        archive,
    }
}

fn entry(conversation: ConversationId, byte: u8) -> NewArchiveEntry {
    NewArchiveEntry {
        id: MessageId::generate(),
        conversation,
        ciphertext: vec![byte; 16],
        nonce: ArchiveNonce::parse(&[byte; 12]).unwrap(),
        client_message_id: None,
    }
}

#[tokio::test]
async fn an_account_archives_what_it_read_in_conversations_it_is_or_was_in() {
    let w = world().await;
    let batch = vec![entry(w.dm, 1), entry(w.left, 2)];

    let stored = w
        .store
        .execute(w.alice.id, generation(1), batch.clone())
        .await
        .unwrap();
    let again = w
        .store
        .execute(w.alice.id, generation(1), batch)
        .await
        .unwrap();

    assert_eq!((stored, again), (2, 0));
}

#[tokio::test]
async fn an_upload_naming_a_conversation_the_account_never_held_stores_nothing() {
    let w = world().await;

    let refused = w
        .store
        .execute(
            w.alice.id,
            generation(1),
            vec![entry(w.dm, 1), entry(w.elsewhere, 2)],
        )
        .await;

    assert!(
        matches!(refused, Err(ArchiveError::NotAMember)),
        "{refused:?}"
    );
    assert!(
        w.archive
            .page(w.alice.id, None, 10)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn an_upload_holds_one_to_fifty_entries() {
    let w = world().await;

    let empty = w.store.execute(w.alice.id, generation(1), Vec::new()).await;
    let too_many = w
        .store
        .execute(
            w.alice.id,
            generation(1),
            (0..51).map(|b| entry(w.dm, b)).collect(),
        )
        .await;

    for refused in [empty, too_many] {
        assert!(
            matches!(refused, Err(ArchiveError::Refused(BatchSize))),
            "{refused:?}"
        );
    }
}

#[tokio::test]
async fn the_archive_reads_newest_first_a_page_at_a_time() {
    let w = world().await;
    w.store
        .execute(
            w.alice.id,
            generation(1),
            vec![entry(w.dm, 1), entry(w.dm, 2)],
        )
        .await
        .unwrap();
    w.store
        .execute(w.alice.id, generation(1), vec![entry(w.dm, 3)])
        .await
        .unwrap();

    let first = w.read.execute(w.alice.id, None, Some(2)).await.unwrap();
    let rest = w
        .read
        .execute(w.alice.id, first.next, Some(2))
        .await
        .unwrap();
    let past_the_end = w.read.execute(w.alice.id, rest.next, None).await.unwrap();

    assert_eq!(first.entries.len(), 2);
    assert_eq!(first.entries[0].ciphertext, vec![3; 16]);
    assert_eq!(first.next, Some(first.entries[1].cursor()));
    assert_eq!(rest.entries.len(), 1);
    assert_eq!(
        past_the_end,
        ArchivePage {
            entries: Vec::new(),
            next: None
        }
    );
    assert!(
        w.read
            .execute(w.bob.id, None, None)
            .await
            .unwrap()
            .entries
            .is_empty()
    );
}

#[tokio::test]
async fn clearing_empties_the_callers_archive() {
    let w = world().await;
    w.store
        .execute(
            w.alice.id,
            generation(1),
            vec![entry(w.dm, 1), entry(w.dm, 2)],
        )
        .await
        .unwrap();
    w.store
        .execute(w.bob.id, generation(1), vec![entry(w.dm, 3)])
        .await
        .unwrap();

    let cleared = w.clear.execute(w.alice.id).await.unwrap();

    assert_eq!(cleared, 2);
    assert_eq!(w.archive.page(w.bob.id, None, 10).await.unwrap().len(), 1);
}

#[tokio::test]
async fn an_upload_under_another_generation_than_the_current_one_stores_nothing() {
    let w = world().await;
    let carol = UserId::generate();
    w.archive
        .replace(w.alice.id, &history_key(2), DeviceId::generate())
        .await
        .unwrap();

    let replaced = w
        .store
        .execute(w.alice.id, generation(1), vec![entry(w.dm, 1)])
        .await;
    let ahead = w
        .store
        .execute(w.alice.id, generation(3), vec![entry(w.dm, 1)])
        .await;
    let none_set = w
        .store
        .execute(carol, generation(1), vec![entry(w.dm, 1)])
        .await;

    for refused in [replaced, ahead, none_set] {
        assert!(
            matches!(refused, Err(ArchiveError::Stale(StaleHistoryKey))),
            "{refused:?}"
        );
    }
    assert!(
        w.archive
            .page(w.alice.id, None, 10)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn clearing_keeps_the_key_and_the_next_upload_is_saved_under_it() {
    let w = world().await;
    w.store
        .execute(w.alice.id, generation(1), vec![entry(w.dm, 1)])
        .await
        .unwrap();

    w.clear.execute(w.alice.id).await.unwrap();
    let after = w
        .store
        .execute(w.alice.id, generation(1), vec![entry(w.dm, 2)])
        .await
        .unwrap();

    assert_eq!(
        w.archive
            .current(w.alice.id)
            .await
            .unwrap()
            .map(|held| held.key),
        Some(history_key(1))
    );
    assert_eq!(after, 1);
    assert_eq!(
        w.archive
            .replace(w.alice.id, &history_key(2), DeviceId::generate())
            .await
            .unwrap(),
        KeyReplace::Replaced { erased: 1 },
        "the generation is still the first"
    );
}
