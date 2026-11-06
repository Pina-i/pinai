use std::sync::Arc;

use domain::auth::testing::InMemorySessions;
use domain::e2ee::testing::{InMemoryArchive, InMemoryKeyDirectory};
use domain::e2ee::{
    ApprovalPublicKey, ApprovalRequired, ArchiveNonce, ArchiveStoreError, Attestation, BatchSize,
    DeviceLabel, DeviceRootKey, Devices, HistoryCheckValue, HistoryKey, HistoryKeys, HistorySalt,
    HpkeKeyWrite, KeyReplace, StaleHistoryKey,
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
    devices: Arc<InMemoryKeyDirectory>,
    sessions: Arc<InMemorySessions>,
    /// Alice's device, approved under the first generation: it may set the next.
    laptop: DeviceId,
    /// A session of Alice's naming her laptop.
    on_the_laptop: Bearer,
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
    let devices = Arc::new(InMemoryKeyDirectory::keyed_by(archive.clone()));
    let sessions = Arc::new(InMemorySessions::default());
    let laptop = DeviceId::generate();
    for owner in [alice.id, bob.id] {
        let device = if owner == alice.id {
            laptop
        } else {
            DeviceId::generate()
        };
        registered(&devices, owner, device).await;
        archive
            .replace(
                owner,
                &history_key(1),
                device,
                time::OffsetDateTime::now_utc(),
            )
            .await
            .unwrap();
        devices
            .approved_by_words(owner, device, &history_key(1))
            .await;
    }
    let on_the_laptop = naming(&sessions, alice.id, laptop).await;
    World {
        store: ArchiveMessages::new(
            Arc::new(InMemoryAccounts::with([alice.clone(), bob.clone(), carol])),
            conversations,
            sessions.clone(),
            devices.clone(),
            archive.clone(),
        ),
        read: ReadArchive::new(archive.clone()),
        clear: ClearArchive::new(sessions.clone(), devices.clone(), archive.clone()),
        alice,
        bob,
        dm,
        left,
        elsewhere,
        archive,
        devices,
        sessions,
        laptop,
        on_the_laptop,
    }
}

async fn registered(devices: &InMemoryKeyDirectory, owner: UserId, device: DeviceId) {
    devices
        .attest(
            owner,
            device,
            &DeviceLabel::unknown(),
            None,
            &Attestation {
                root_key: DeviceRootKey::parse(&[1; 32]).unwrap(),
                signature: vec![1; 64],
                kid: "key-1".to_owned(),
                issued_at: time::OffsetDateTime::now_utc(),
                expires_at: time::OffsetDateTime::now_utc() + time::Duration::days(365),
            },
            &HpkeKeyWrite::Clear,
        )
        .await
        .unwrap();
}

/// A live session of `owner`'s, naming no device.
fn session_of(sessions: &InMemorySessions, owner: UserId) -> Bearer {
    let now = time::OffsetDateTime::now_utc();
    Bearer {
        user: owner,
        session: sessions.live_at(owner, now),
        authenticated_at: now,
    }
}

/// The same, naming `device`.
async fn naming(sessions: &InMemorySessions, owner: UserId, device: DeviceId) -> Bearer {
    let bearer = session_of(sessions, owner);
    sessions
        .link(
            owner,
            bearer.session,
            device,
            time::OffsetDateTime::now_utc(),
        )
        .await
        .unwrap();
    bearer
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
        .execute(&w.on_the_laptop, generation(1), batch.clone())
        .await
        .unwrap();
    let again = w
        .store
        .execute(&w.on_the_laptop, generation(1), batch)
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
            &w.on_the_laptop,
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

    let empty = w
        .store
        .execute(&w.on_the_laptop, generation(1), Vec::new())
        .await;
    let too_many = w
        .store
        .execute(
            &w.on_the_laptop,
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
            &w.on_the_laptop,
            generation(1),
            vec![entry(w.dm, 1), entry(w.dm, 2)],
        )
        .await
        .unwrap();
    w.store
        .execute(&w.on_the_laptop, generation(1), vec![entry(w.dm, 3)])
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
            &w.on_the_laptop,
            generation(1),
            vec![entry(w.dm, 1), entry(w.dm, 2)],
        )
        .await
        .unwrap();
    w.archive
        .store(w.bob.id, generation(1), &[entry(w.dm, 3)])
        .await
        .unwrap();

    let cleared = w.clear.execute(&w.on_the_laptop).await.unwrap();

    assert_eq!(cleared, 2);
    assert_eq!(w.archive.page(w.bob.id, None, 10).await.unwrap().len(), 1);
}

#[tokio::test]
async fn only_an_approved_device_clears_once_the_account_has_a_key() {
    let w = world().await;
    w.store
        .execute(&w.on_the_laptop, generation(1), vec![entry(w.dm, 1)])
        .await
        .unwrap();
    let fresh = DeviceId::generate();
    registered(&w.devices, w.alice.id, fresh).await;
    let on_the_fresh_one = naming(&w.sessions, w.alice.id, fresh).await;
    let unnamed = session_of(&w.sessions, w.alice.id);

    let by_the_fresh_one = w.clear.execute(&on_the_fresh_one).await;
    let by_the_unnamed = w.clear.execute(&unnamed).await;
    let kept = w.archive.page(w.alice.id, None, 10).await.unwrap().len();
    let by_the_laptop = w.clear.execute(&w.on_the_laptop).await;

    for refused in [by_the_fresh_one, by_the_unnamed] {
        assert!(
            matches!(
                refused,
                Err(ArchiveError::ApprovalRequired(ApprovalRequired))
            ),
            "{refused:?}"
        );
    }
    assert_eq!(kept, 1, "a refusal erases nothing");
    assert_eq!(by_the_laptop.unwrap(), 1);
}

/// The archive as a replacement landing between the clear's decision and its erase leaves it: the
/// next generation set, and `saved` archived under it.
struct ReplacedMeanwhile {
    inner: Arc<InMemoryArchive>,
    laptop: DeviceId,
    saved: NewArchiveEntry,
}

#[async_trait::async_trait]
impl HistoryArchive for ReplacedMeanwhile {
    async fn store(
        &self,
        owner: UserId,
        generation: HistoryGeneration,
        entries: &[NewArchiveEntry],
    ) -> Result<Archived, ArchiveStoreError> {
        self.inner.store(owner, generation, entries).await
    }

    async fn page(
        &self,
        owner: UserId,
        after: Option<ArchiveCursor>,
        limit: usize,
    ) -> Result<Vec<ArchiveEntry>, ArchiveStoreError> {
        self.inner.page(owner, after, limit).await
    }

    async fn clear(
        &self,
        owner: UserId,
        generation: HistoryGeneration,
    ) -> Result<Cleared, ArchiveStoreError> {
        let now = time::OffsetDateTime::now_utc();
        self.inner
            .replace(owner, &history_key(2), self.laptop, now)
            .await
            .unwrap();
        self.inner
            .store(
                owner,
                history_key(2).generation,
                std::slice::from_ref(&self.saved),
            )
            .await
            .unwrap();
        self.inner.clear(owner, generation).await
    }
}

#[tokio::test]
async fn a_clear_erases_nothing_of_a_generation_set_since_it_was_decided() {
    let w = world().await;
    w.store
        .execute(&w.on_the_laptop, generation(1), vec![entry(w.dm, 1)])
        .await
        .unwrap();
    let saved = entry(w.dm, 2);
    let clear = ClearArchive::new(
        w.sessions.clone(),
        w.devices.clone(),
        Arc::new(ReplacedMeanwhile {
            inner: w.archive.clone(),
            laptop: w.laptop,
            saved: saved.clone(),
        }),
    );

    let cleared = clear.execute(&w.on_the_laptop).await;

    assert!(
        matches!(cleared, Err(ArchiveError::Stale(StaleHistoryKey))),
        "{cleared:?}"
    );
    let left = w.archive.page(w.alice.id, None, 10).await.unwrap();
    assert_eq!(
        left.iter().map(|e| e.id).collect::<Vec<_>>(),
        vec![saved.id],
        "the new generation's entry stays"
    );
}

#[tokio::test]
async fn an_account_with_no_history_key_clears_from_any_session() {
    let w = world().await;
    let carol = UserId::generate();

    let cleared = w.clear.execute(&session_of(&w.sessions, carol)).await;

    assert_eq!(cleared.unwrap(), 0);
}

#[tokio::test]
async fn an_upload_under_another_generation_than_the_current_one_stores_nothing() {
    let w = world().await;
    let carol = UserId::generate();
    w.archive
        .replace(
            w.alice.id,
            &history_key(2),
            w.laptop,
            time::OffsetDateTime::now_utc(),
        )
        .await
        .unwrap();

    let replaced = w
        .store
        .execute(&w.on_the_laptop, generation(1), vec![entry(w.dm, 1)])
        .await;
    let ahead = w
        .store
        .execute(&w.on_the_laptop, generation(3), vec![entry(w.dm, 1)])
        .await;
    let none_set = w
        .store
        .execute(
            &session_of(&w.sessions, carol),
            generation(1),
            vec![entry(w.dm, 1)],
        )
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
async fn only_an_approved_device_archives_once_the_account_has_a_key() {
    let w = world().await;
    let fresh = DeviceId::generate();
    registered(&w.devices, w.alice.id, fresh).await;
    let on_the_fresh_one = naming(&w.sessions, w.alice.id, fresh).await;
    let unnamed = session_of(&w.sessions, w.alice.id);
    let batch = vec![entry(w.dm, 1)];

    let by_the_fresh_one = w
        .store
        .execute(&on_the_fresh_one, generation(1), batch.clone())
        .await;
    let by_the_unnamed = w
        .store
        .execute(&unnamed, generation(1), batch.clone())
        .await;
    let stored = w.archive.page(w.alice.id, None, 10).await.unwrap().len();
    let by_the_laptop = w
        .store
        .execute(&w.on_the_laptop, generation(1), batch)
        .await;

    for refused in [by_the_fresh_one, by_the_unnamed] {
        assert!(
            matches!(
                refused,
                Err(ArchiveError::ApprovalRequired(ApprovalRequired))
            ),
            "{refused:?}"
        );
    }
    assert_eq!(stored, 0, "a refusal stores nothing");
    assert_eq!(by_the_laptop.unwrap(), 1, "the ids are still the laptop's");
}

#[tokio::test]
async fn a_generation_not_the_current_one_is_stale_before_any_approval_is_asked() {
    let w = world().await;
    let fresh = DeviceId::generate();
    registered(&w.devices, w.alice.id, fresh).await;
    let on_the_fresh_one = naming(&w.sessions, w.alice.id, fresh).await;
    let unnamed = session_of(&w.sessions, w.alice.id);

    for bearer in [on_the_fresh_one, unnamed] {
        let refused = w
            .store
            .execute(&bearer, generation(2), vec![entry(w.dm, 1)])
            .await;

        assert!(
            matches!(refused, Err(ArchiveError::Stale(StaleHistoryKey))),
            "{refused:?}"
        );
    }
}

#[tokio::test]
async fn clearing_keeps_the_key_and_the_next_upload_is_saved_under_it() {
    let w = world().await;
    w.store
        .execute(&w.on_the_laptop, generation(1), vec![entry(w.dm, 1)])
        .await
        .unwrap();

    w.clear.execute(&w.on_the_laptop).await.unwrap();
    let after = w
        .store
        .execute(&w.on_the_laptop, generation(1), vec![entry(w.dm, 2)])
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
            .replace(
                w.alice.id,
                &history_key(2),
                w.laptop,
                time::OffsetDateTime::now_utc()
            )
            .await
            .unwrap(),
        KeyReplace::Replaced {
            erased: 1,
            closed: vec![]
        },
        "the generation is still the first"
    );
}
