use domain::ConversationId;
use domain::auth::Sessions;
use domain::auth::testing::InMemorySessions;
use domain::e2ee::testing::{
    InMemoryArchive, InMemoryKeyDirectory, PlainEd25519Verifier, RecordingDeviceTrustNotifier,
    plain_signature,
};
use domain::e2ee::{
    ApprovalBy, ApprovalFacts, ApprovalPublicKey, ArchiveNonce, Archived, Attestation,
    DeviceApprovals, DeviceLabel, DeviceRequired, DeviceRootKey, HistoryArchive, HistoryCheckValue,
    HistorySalt, HpkeKeyWrite, NewArchiveEntry, approval_bytes, may_approve,
};
use domain::identity::ActorUri;
use time::Duration;

use super::*;

struct World {
    alice: UserId,
    bob: UserId,
    sessions: Arc<InMemorySessions>,
    devices: Arc<InMemoryKeyDirectory>,
    archive: Arc<InMemoryArchive>,
    load: LoadHistoryKey,
    set: SetHistoryKey,
    report: ReportHistoryKey,
}

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(OffsetDateTime::now_utc().unix_timestamp()).unwrap()
}

fn generation(raw: i64) -> HistoryGeneration {
    HistoryGeneration::parse(raw).unwrap()
}

fn history_key(raw: i64, byte: u8) -> HistoryKey {
    HistoryKey {
        generation: generation(raw),
        salt: HistorySalt::parse(&[byte; 16]).unwrap(),
        check_value: HistoryCheckValue::parse(&[byte; 32]).unwrap(),
        approval_public_key: ApprovalPublicKey::parse(&[byte; 32]).unwrap(),
    }
}

fn world() -> World {
    let sessions = Arc::new(InMemorySessions::default());
    let archive = Arc::new(InMemoryArchive::default());
    let devices = Arc::new(InMemoryKeyDirectory::keyed_by(archive.clone()));
    World {
        alice: UserId::generate(),
        bob: UserId::generate(),
        load: LoadHistoryKey::new(archive.clone()),
        set: SetHistoryKey::new(
            sessions.clone(),
            archive.clone(),
            devices.clone(),
            Arc::new(RecordingDeviceTrustNotifier::default()),
        ),
        report: ReportHistoryKey::new(sessions.clone(), devices.clone(), archive.clone()),
        sessions,
        devices,
        archive,
    }
}

impl World {
    /// A session of `who`'s, naming `device` when given, its password typed `minutes_ago`.
    async fn signed_in(&self, who: UserId, device: Option<DeviceId>, minutes_ago: i64) -> Bearer {
        let session = self.sessions.live_at(who, now());
        if let Some(device) = device {
            self.sessions
                .link(who, session, device, now())
                .await
                .unwrap();
        }
        Bearer {
            user: who,
            session,
            authenticated_at: now() - Duration::minutes(minutes_ago),
        }
    }

    /// A device of `who`'s, attested.
    async fn device(&self, who: UserId) -> DeviceId {
        let id = DeviceId::generate();
        let attestation = Attestation {
            root_key: DeviceRootKey::parse(&[1; 32]).unwrap(),
            signature: vec![1; 64],
            kid: "key-1".to_owned(),
            issued_at: now(),
            expires_at: now() + Duration::days(365),
        };
        self.devices
            .attest(
                who,
                id,
                &DeviceLabel::unknown(),
                None,
                &attestation,
                &HpkeKeyWrite::Clear,
            )
            .await
            .unwrap();
        id
    }

    /// A session of `who`'s naming a new device of theirs, its password just typed.
    async fn on_a_device(&self, who: UserId) -> (DeviceId, Bearer) {
        let device = self.device(who).await;
        (device, self.signed_in(who, Some(device), 0).await)
    }

    async fn archived(&self, owner: UserId, generation: HistoryGeneration) -> Archived {
        let entry = NewArchiveEntry {
            id: domain::MessageId::generate(),
            conversation: ConversationId::generate(),
            ciphertext: vec![1; 16],
            nonce: ArchiveNonce::parse(&[1; 12]).unwrap(),
            client_message_id: None,
        };
        self.archive
            .store(owner, generation, &[entry])
            .await
            .unwrap()
    }

    /// `device` approved by `key`'s words, as a device holding them approves itself.
    async fn approved_by_words(&self, who: UserId, device: DeviceId, key: &HistoryKey) {
        let actor = ActorUri::parse("https://idp.test/users/alice_t3st0").unwrap();
        let signer = Devices::find(&*self.devices, device)
            .await
            .unwrap()
            .unwrap();
        let root = signer.attestation.as_ref().unwrap().root_key.clone();
        let signature = plain_signature(
            &key.approval_public_key,
            &approval_bytes(&actor, device, &root),
        );
        let facts = ApprovalFacts {
            actor: &actor,
            signer: &signer,
            approved: None,
            current: Some(key),
        };
        let checked = may_approve(
            device,
            ApprovalBy::Passphrase(key.generation),
            signature,
            facts,
            &PlainEd25519Verifier,
        )
        .unwrap();
        self.devices.approve(who, &checked).await.unwrap();
    }

    async fn held(&self, device: DeviceId) -> Option<HistoryGeneration> {
        Devices::find(&*self.devices, device)
            .await
            .unwrap()
            .unwrap()
            .history_generation
    }
}

#[tokio::test]
async fn there_is_no_key_until_a_device_sets_the_first_and_then_it_names_that_device() {
    let w = world();
    let (laptop, bearer) = w.on_a_device(w.alice).await;

    let before = w.load.execute(w.alice).await;
    w.set
        .execute(&bearer, history_key(1, 1), now())
        .await
        .unwrap();

    assert!(matches!(before, Err(ArchiveError::NoKey)), "{before:?}");
    assert_eq!(
        w.load.execute(w.alice).await.unwrap(),
        HeldHistoryKey {
            key: history_key(1, 1),
            set_by: Some(laptop),
        }
    );
    assert!(matches!(
        w.load.execute(w.bob).await,
        Err(ArchiveError::NoKey)
    ));
}

#[tokio::test]
async fn the_first_device_sets_generation_one_without_a_recent_password() {
    let w = world();
    let laptop = w.device(w.alice).await;
    let long_ago = w.signed_in(w.alice, Some(laptop), 60).await;

    let set = w.set.execute(&long_ago, history_key(1, 1), now()).await;

    assert!(set.is_ok(), "{set:?}");
}

#[tokio::test]
async fn a_session_that_named_no_device_sets_no_key() {
    let w = world();
    let unnamed = w.signed_in(w.alice, None, 0).await;

    let refused = w.set.execute(&unnamed, history_key(1, 1), now()).await;

    assert!(
        matches!(refused, Err(ArchiveError::DeviceRequired(DeviceRequired))),
        "{refused:?}"
    );
    assert!(matches!(
        w.load.execute(w.alice).await,
        Err(ArchiveError::NoKey)
    ));
}

#[tokio::test]
async fn a_later_generation_takes_a_recent_password_and_erases_the_archive() {
    let w = world();
    let laptop = w.device(w.alice).await;
    let first = w.signed_in(w.alice, Some(laptop), 0).await;
    w.set
        .execute(&first, history_key(1, 1), now())
        .await
        .unwrap();
    w.approved_by_words(w.alice, laptop, &history_key(1, 1))
        .await;
    w.archived(w.alice, generation(1)).await;
    let (long_ago, recent) = (
        w.signed_in(w.alice, Some(laptop), 11).await,
        w.signed_in(w.alice, Some(laptop), 1).await,
    );

    let refused = w.set.execute(&long_ago, history_key(2, 2), now()).await;
    let kept = w.archive.page(w.alice, None, 10).await.unwrap().len();
    w.set
        .execute(&recent, history_key(2, 2), now())
        .await
        .unwrap();

    assert!(
        matches!(refused, Err(ArchiveError::RecentSignInRequired)),
        "{refused:?}"
    );
    assert_eq!(kept, 1, "a refusal erases nothing");
    assert_eq!(
        w.load.execute(w.alice).await.unwrap().key,
        history_key(2, 2)
    );
    assert!(w.archive.page(w.alice, None, 10).await.unwrap().is_empty());
    assert_eq!(w.archived(w.alice, generation(1)).await, Archived::Stale);
}

#[tokio::test]
async fn only_the_generation_after_the_current_one_is_set_and_a_retry_succeeds() {
    let w = world();
    let (_, bearer) = w.on_a_device(w.alice).await;

    let skipping = w.set.execute(&bearer, history_key(2, 2), now()).await;
    w.set
        .execute(&bearer, history_key(1, 1), now())
        .await
        .unwrap();
    let raced = w.set.execute(&bearer, history_key(1, 9), now()).await;
    let retried = w.set.execute(&bearer, history_key(1, 1), now()).await;

    assert!(
        matches!(skipping, Err(ArchiveError::KeyConflict { current: None })),
        "{skipping:?}"
    );
    assert!(
        matches!(raced, Err(ArchiveError::KeyConflict { current: Some(g) }) if g == generation(1)),
        "{raced:?}"
    );
    assert!(retried.is_ok(), "the very key held: {retried:?}");
    assert_eq!(
        w.load.execute(w.alice).await.unwrap().key,
        history_key(1, 1)
    );
}

#[tokio::test]
async fn a_device_reports_the_current_generation_from_its_own_session() {
    let w = world();
    let (laptop, bearer) = w.on_a_device(w.alice).await;
    w.set
        .execute(&bearer, history_key(1, 1), now())
        .await
        .unwrap();

    w.report
        .execute(&bearer, laptop, generation(1))
        .await
        .unwrap();

    assert_eq!(w.held(laptop).await, Some(generation(1)));
}

#[tokio::test]
async fn a_session_reports_for_the_device_it_named_only() {
    let w = world();
    let (laptop, laptops) = w.on_a_device(w.alice).await;
    let phone = w.device(w.alice).await;
    w.set
        .execute(&laptops, history_key(1, 1), now())
        .await
        .unwrap();
    let unnamed = w.signed_in(w.alice, None, 0).await;

    let for_another = w.report.execute(&laptops, phone, generation(1)).await;
    let from_none = w.report.execute(&unnamed, phone, generation(1)).await;

    assert!(
        matches!(for_another, Err(KeyDirectoryError::NotTheSessionsDevice)),
        "{for_another:?}"
    );
    assert!(
        matches!(
            from_none,
            Err(KeyDirectoryError::DeviceRequired(DeviceRequired))
        ),
        "{from_none:?}"
    );
    assert_eq!((w.held(laptop).await, w.held(phone).await), (None, None));
}

#[tokio::test]
async fn only_the_current_generation_is_reported() {
    let w = world();
    let (laptop, bearer) = w.on_a_device(w.alice).await;

    let none_set = w.report.execute(&bearer, laptop, generation(1)).await;
    w.set
        .execute(&bearer, history_key(1, 1), now())
        .await
        .unwrap();
    let ahead = w.report.execute(&bearer, laptop, generation(2)).await;

    for refused in [none_set, ahead] {
        assert!(
            matches!(refused, Err(KeyDirectoryError::StaleHistoryKey(_))),
            "{refused:?}"
        );
    }
    assert_eq!(w.held(laptop).await, None);
}
