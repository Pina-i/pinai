use std::sync::Arc;

use domain::e2ee::testing::InMemoryArchive;
use domain::e2ee::{ArchiveNonce, BatchSize};
use domain::identity::Account;
use domain::identity::testing::{InMemoryAccounts, account};
use domain::messaging::testing::InMemoryMessaging;
use domain::messaging::{Member, Role};
use domain::{ConversationId, MessageId};

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
    load_salt: LoadArchiveSalt,
    set_salt: SetArchiveSalt,
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
        .remove_member(left, &alice.actor_uri)
        .await
        .unwrap();
    let elsewhere = conversations
        .open_dm(&bob.actor_uri, &carol.actor_uri, None)
        .await
        .unwrap();
    let archive = Arc::new(InMemoryArchive::default());
    World {
        store: ArchiveMessages::new(
            Arc::new(InMemoryAccounts::with([alice.clone(), bob.clone(), carol])),
            conversations,
            archive.clone(),
        ),
        read: ReadArchive::new(archive.clone()),
        clear: ClearArchive::new(archive.clone()),
        load_salt: LoadArchiveSalt::new(archive.clone()),
        set_salt: SetArchiveSalt::new(archive.clone()),
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

    let stored = w.store.execute(w.alice.id, batch.clone()).await.unwrap();
    let again = w.store.execute(w.alice.id, batch).await.unwrap();

    assert_eq!((stored, again), (2, 0));
}

#[tokio::test]
async fn an_upload_naming_a_conversation_the_account_never_held_stores_nothing() {
    let w = world().await;

    let refused = w
        .store
        .execute(w.alice.id, vec![entry(w.dm, 1), entry(w.elsewhere, 2)])
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

    let empty = w.store.execute(w.alice.id, Vec::new()).await;
    let too_many = w
        .store
        .execute(w.alice.id, (0..51).map(|b| entry(w.dm, b)).collect())
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
        .execute(w.alice.id, vec![entry(w.dm, 1), entry(w.dm, 2)])
        .await
        .unwrap();
    w.store
        .execute(w.alice.id, vec![entry(w.dm, 3)])
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
        .execute(w.alice.id, vec![entry(w.dm, 1), entry(w.dm, 2)])
        .await
        .unwrap();
    w.store
        .execute(w.bob.id, vec![entry(w.dm, 3)])
        .await
        .unwrap();

    let cleared = w.clear.execute(w.alice.id).await.unwrap();

    assert_eq!(cleared, 2);
    assert_eq!(w.archive.page(w.bob.id, None, 10).await.unwrap().len(), 1);
}

#[tokio::test]
async fn the_salt_is_set_once_and_read_back() {
    let w = world().await;
    let (first, second) = (
        ArchiveSalt::parse(&[1; 16]).unwrap(),
        ArchiveSalt::parse(&[2; 16]).unwrap(),
    );

    let unset = w.load_salt.execute(w.alice.id).await;
    let set = w.set_salt.execute(w.alice.id, first.clone()).await.unwrap();
    let kept = w.set_salt.execute(w.alice.id, second).await.unwrap();

    assert!(matches!(unset, Err(ArchiveError::NoSalt)), "{unset:?}");
    assert_eq!((&set, &kept), (&first, &first));
    assert_eq!(w.load_salt.execute(w.alice.id).await.unwrap(), first);
}
