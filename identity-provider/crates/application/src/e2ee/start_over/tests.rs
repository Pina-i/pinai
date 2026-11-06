use domain::auth::testing::{InMemorySessions, RecordingSessionNotifier};
use domain::auth::{RevokedReason, Session};
use domain::e2ee::testing::{
    InMemoryArchive, InMemoryKeyDirectory, PlainEd25519Verifier, RecordingDeviceTrustNotifier,
    SentTrust, plain_signature,
};
use domain::e2ee::{
    ApprovalBy, ApprovalFacts, ApprovalPublicKey, ApprovalRequired, ArchiveError,
    ArchiveStoreError, Attestation, DeviceLabel, DeviceRootKey, HeldHistoryKey, HistoryCheckValue,
    HistoryGeneration, HistoryKey, HistoryKeys, HistorySalt, HpkeKeyWrite, KeyReplace,
    START_OVER_WAIT, StartOverEnd, approval_bytes, may_approve,
};
use domain::identity::testing::InMemoryAccounts;
use domain::identity::{Account, ActorUri};
use domain::{DeviceId, UserId};
use std::sync::Mutex;
use time::Duration;

use super::*;
use crate::e2ee::{ApproveDevice, RevokeDevice, SetHistoryKey};

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(OffsetDateTime::now_utc().unix_timestamp()).unwrap()
}

fn history_key(generation: i64, byte: u8) -> HistoryKey {
    HistoryKey {
        generation: HistoryGeneration::parse(generation).unwrap(),
        salt: HistorySalt::parse(&[byte; 16]).unwrap(),
        check_value: HistoryCheckValue::parse(&[byte; 32]).unwrap(),
        approval_public_key: ApprovalPublicKey::parse(&[byte; 32]).unwrap(),
    }
}

struct World {
    alice: UserId,
    sessions: Arc<InMemorySessions>,
    devices: Arc<InMemoryKeyDirectory>,
    archive: Arc<InMemoryArchive>,
    notifier: Arc<RecordingDeviceTrustNotifier>,
    ask: AskToStartOver,
    load: LoadStartOver,
    end: EndStartOver,
    sweep: SweepStartOverRequests,
    set: SetHistoryKey,
    revoke: RevokeDevice,
    approve: ApproveDevice,
}

fn actor() -> ActorUri {
    ActorUri::parse("https://idp.test/users/alice_t3st0").unwrap()
}

fn world_keyed_by(
    keys: impl FnOnce(Arc<InMemoryArchive>, Arc<InMemoryKeyDirectory>) -> Arc<dyn HistoryKeys>,
) -> World {
    let sessions = Arc::new(InMemorySessions::default());
    let archive = Arc::new(InMemoryArchive::watching(sessions.clone()));
    let devices = Arc::new(InMemoryKeyDirectory::keyed_by(archive.clone()));
    let notifier = Arc::new(RecordingDeviceTrustNotifier::default());
    let alice = UserId::generate();
    let accounts = Arc::new(InMemoryAccounts::with([Account {
        id: alice,
        actor_uri: actor(),
        username: "alice_t3st0".to_owned(),
        display_name: Some("Alice".to_owned()),
        avatar_url: None,
    }]));
    World {
        alice,
        approve: ApproveDevice::new(
            accounts,
            sessions.clone(),
            devices.clone(),
            archive.clone(),
            devices.clone(),
            Arc::new(PlainEd25519Verifier),
            notifier.clone(),
        ),
        ask: AskToStartOver::new(
            sessions.clone(),
            devices.clone(),
            devices.clone(),
            devices.clone(),
            notifier.clone(),
        ),
        load: LoadStartOver::new(
            sessions.clone(),
            devices.clone(),
            devices.clone(),
            devices.clone(),
        ),
        end: EndStartOver::new(
            sessions.clone(),
            devices.clone(),
            devices.clone(),
            devices.clone(),
            notifier.clone(),
        ),
        sweep: SweepStartOverRequests::new(devices.clone()),
        set: SetHistoryKey::new(
            sessions.clone(),
            keys(archive.clone(), devices.clone()),
            devices.clone(),
            notifier.clone(),
        ),
        revoke: RevokeDevice::new(
            devices.clone(),
            sessions.clone(),
            devices.clone(),
            Arc::new(RecordingSessionNotifier::default()),
            notifier.clone(),
        ),
        sessions,
        devices,
        archive,
        notifier,
    }
}

fn world() -> World {
    world_keyed_by(|archive, _| archive)
}

/// A device on a session of its own, its password typed `at`.
struct OnDevice {
    id: DeviceId,
    bearer: Bearer,
}

impl World {
    /// A device of alice's, its root key made of `root`s, signed in `at`.
    async fn device(&self, root: u8, at: OffsetDateTime) -> OnDevice {
        let id = DeviceId::generate();
        let attestation = Attestation {
            root_key: DeviceRootKey::parse(&[root; 32]).unwrap(),
            signature: vec![1; 64],
            kid: "key-1".to_owned(),
            issued_at: at,
            expires_at: at + Duration::days(365),
        };
        let label = DeviceLabel {
            name: format!("Device {root}"),
            kind: domain::e2ee::DeviceKind::Laptop,
        };
        self.devices
            .attest(
                self.alice,
                id,
                &label,
                None,
                &attestation,
                &HpkeKeyWrite::Clear,
            )
            .await
            .unwrap();
        let session = self.sessions.live_at(self.alice, at);
        self.sessions
            .link(self.alice, session, id, at)
            .await
            .unwrap();
        OnDevice {
            id,
            bearer: Bearer {
                user: self.alice,
                session,
                authenticated_at: at,
            },
        }
    }

    /// The account's laptop, which set generation 1 `at` and is approved by its words.
    async fn laptop(&self, at: OffsetDateTime) -> OnDevice {
        let laptop = self.device(1, at).await;
        let first = history_key(1, 1);
        self.set
            .execute(&laptop.bearer, first.clone(), at)
            .await
            .unwrap();
        let actor = actor();
        let signer = Devices::find(&*self.devices, laptop.id)
            .await
            .unwrap()
            .unwrap();
        let root = signer.attestation.as_ref().unwrap().root_key.clone();
        let facts = ApprovalFacts {
            actor: &actor,
            signer: &signer,
            approved: None,
            current: Some(&first),
        };
        let approval = may_approve(
            laptop.id,
            ApprovalBy::Passphrase(first.generation),
            plain_signature(
                &first.approval_public_key,
                &approval_bytes(&actor, laptop.id, &root),
            ),
            facts,
            &PlainEd25519Verifier,
        )
        .unwrap();
        self.devices.approve(self.alice, &approval).await.unwrap();
        laptop
    }

    /// `device`'s password typed again `at`.
    fn typed_at(&self, device: &OnDevice, at: OffsetDateTime) -> Bearer {
        Bearer {
            authenticated_at: at,
            ..device.bearer
        }
    }

    async fn used(&self, device: &OnDevice, at: OffsetDateTime) {
        self.sessions
            .touch(device.bearer.session, at)
            .await
            .unwrap();
    }

    async fn held(&self) -> HeldHistoryKey {
        self.archive.current(self.alice).await.unwrap().unwrap()
    }

    fn sent(&self) -> Vec<SentTrust> {
        self.notifier.sent()
    }
}

#[tokio::test]
async fn a_device_not_approved_asks_and_only_the_approved_devices_are_told() {
    let w = world();
    let t = now();
    let laptop = w.laptop(t).await;
    let fresh = w.device(2, t).await;
    w.sessions.live_at(w.alice, t);

    let asked = w.ask.execute(&fresh.bearer, t).await.unwrap();

    assert!(asked.opened);
    assert_eq!(
        (asked.request.device, asked.request.created_at),
        (fresh.id, t)
    );
    assert_eq!(asked.ready_at, t + START_OVER_WAIT);
    assert_eq!(
        w.sent(),
        vec![SentTrust::StartOverRequested {
            owner: w.alice,
            to: vec![laptop.bearer.session],
            request: asked.request.id,
            device: fresh.id,
            display_name: "Device 2".to_owned(),
            ready_at: t + START_OVER_WAIT,
        }]
    );
}

#[tokio::test]
async fn asking_again_answers_the_open_request_and_tells_nobody_again() {
    let w = world();
    let t = now();
    w.laptop(t).await;
    let fresh = w.device(2, t).await;
    let first = w.ask.execute(&fresh.bearer, t).await.unwrap();

    let again = w
        .ask
        .execute(&fresh.bearer, t + Duration::minutes(1))
        .await
        .unwrap();

    assert!(!again.opened);
    assert_eq!(again.request, first.request);
    assert_eq!(w.sent().len(), 1);
}

#[tokio::test]
async fn another_device_asking_while_one_is_open_is_refused() {
    let w = world();
    let t = now();
    w.laptop(t).await;
    let (fresh, other) = (w.device(2, t).await, w.device(3, t).await);
    w.ask.execute(&fresh.bearer, t).await.unwrap();

    let refused = w.ask.execute(&other.bearer, t).await;

    assert!(
        matches!(
            refused,
            Err(KeyDirectoryError::StartOver(StartOverRefusal::Pending))
        ),
        "{refused:?}"
    );
}

#[tokio::test]
async fn only_a_device_not_approved_on_an_account_with_a_key_asks() {
    let w = world();
    let t = now();
    let fresh = w.device(2, t).await;
    let before_any_key = w.ask.execute(&fresh.bearer, t).await;
    let laptop = w.laptop(t).await;
    let unnamed = Bearer {
        session: w.sessions.live_at(w.alice, t),
        ..fresh.bearer
    };

    let approved = w.ask.execute(&laptop.bearer, t).await;
    let no_device = w.ask.execute(&unnamed, t).await;

    assert!(
        matches!(
            before_any_key,
            Err(KeyDirectoryError::StartOver(StartOverRefusal::NoHistoryKey))
        ),
        "{before_any_key:?}"
    );
    assert!(
        matches!(
            approved,
            Err(KeyDirectoryError::StartOver(
                StartOverRefusal::AlreadyApproved
            ))
        ),
        "{approved:?}"
    );
    assert!(
        matches!(no_device, Err(KeyDirectoryError::DeviceRequired(_))),
        "{no_device:?}"
    );
    assert_eq!(w.sent(), vec![]);
}

#[tokio::test]
async fn the_asker_and_the_approved_devices_read_the_request_as_of_now() {
    let w = world();
    let t = now();
    let laptop = w.laptop(t).await;
    let (fresh, other) = (w.device(2, t).await, w.device(3, t).await);
    let none = w.load.execute(&fresh.bearer).await;
    let asked = w.ask.execute(&fresh.bearer, t).await.unwrap();
    w.used(&laptop, t + Duration::days(2)).await;

    let by_the_asker = w.load.execute(&fresh.bearer).await.unwrap();
    let by_the_laptop = w.load.execute(&laptop.bearer).await.unwrap();
    let by_another = w.load.execute(&other.bearer).await;

    assert!(
        matches!(
            none,
            Err(KeyDirectoryError::StartOver(StartOverRefusal::NotFound))
        ),
        "{none:?}"
    );
    let pending = PendingStartOver {
        request: asked.request,
        display_name: "Device 2".to_owned(),
        ready_at: t + Duration::days(2) + START_OVER_WAIT,
    };
    assert_eq!(by_the_asker, pending);
    assert_eq!(by_the_laptop, pending);
    assert!(
        matches!(
            by_another,
            Err(KeyDirectoryError::ApprovalRequired(ApprovalRequired))
        ),
        "{by_another:?}"
    );
}

#[tokio::test]
async fn an_approved_device_cancels_the_request_and_the_asker_is_told() {
    let w = world();
    let t = now();
    let laptop = w.laptop(t).await;
    let fresh = w.device(2, t).await;
    let asked = w.ask.execute(&fresh.bearer, t).await.unwrap();

    w.end
        .execute(&laptop.bearer, asked.request.id, t)
        .await
        .unwrap();
    let later = t + START_OVER_WAIT * 2;
    let put = w
        .set
        .execute(&w.typed_at(&fresh, later), history_key(2, 2), later)
        .await;

    assert_eq!(
        w.sent().last(),
        Some(&SentTrust::StartOverCancelled {
            owner: w.alice,
            to: vec![laptop.bearer.session, fresh.bearer.session],
            request: asked.request.id,
            reason: StartOverEnd::Cancelled,
        })
    );
    let ended = w
        .devices
        .request(w.alice, asked.request.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        ended.ended.map(|ending| ending.how),
        Some(StartOverEnd::Cancelled)
    );
    assert!(
        matches!(
            put,
            Err(ArchiveError::StartOver(StartOverRefusal::Required))
        ),
        "{put:?}"
    );
}

#[tokio::test]
async fn the_asker_withdraws_its_request_and_no_other_device_ends_it() {
    let w = world();
    let t = now();
    w.laptop(t).await;
    let (fresh, other) = (w.device(2, t).await, w.device(3, t).await);
    let asked = w.ask.execute(&fresh.bearer, t).await.unwrap();

    let by_another = w.end.execute(&other.bearer, asked.request.id, t).await;
    w.end
        .execute(&fresh.bearer, asked.request.id, t)
        .await
        .unwrap();
    let again = w.end.execute(&fresh.bearer, asked.request.id, t).await;
    let unknown = w
        .end
        .execute(&fresh.bearer, StartOverRequestId::generate(), t)
        .await;

    assert!(
        matches!(
            by_another,
            Err(KeyDirectoryError::ApprovalRequired(ApprovalRequired))
        ),
        "{by_another:?}"
    );
    assert!(
        matches!(
            again,
            Err(KeyDirectoryError::StartOver(StartOverRefusal::Ended))
        ),
        "{again:?}"
    );
    assert!(
        matches!(
            unknown,
            Err(KeyDirectoryError::StartOver(StartOverRefusal::NotFound))
        ),
        "{unknown:?}"
    );
}

#[tokio::test]
async fn a_start_over_waits_a_week_past_each_use_of_an_approved_device_then_sets_the_key() {
    let w = world();
    let t = now();
    let laptop = w.laptop(t).await;
    let fresh = w.device(2, t).await;
    let asked = w.ask.execute(&fresh.bearer, t).await.unwrap();
    let put_at = async |at: OffsetDateTime| {
        w.set
            .execute(&w.typed_at(&fresh, at), history_key(2, 2), at)
            .await
    };

    let first_try = put_at(t + Duration::days(1)).await;
    w.used(&laptop, t + Duration::days(3)).await;
    let a_week_after_opening = put_at(t + START_OVER_WAIT).await;
    let ready = put_at(t + Duration::days(3) + START_OVER_WAIT).await;

    for (refused, ready_at) in [
        (first_try, t + START_OVER_WAIT),
        (
            a_week_after_opening,
            t + Duration::days(3) + START_OVER_WAIT,
        ),
    ] {
        assert!(
            matches!(
                refused,
                Err(ArchiveError::StartOver(StartOverRefusal::NotReady { ready_at: at })) if at == ready_at
            ),
            "{refused:?}"
        );
    }
    assert!(ready.is_ok(), "{ready:?}");
    let held = w.held().await;
    assert_eq!((held.key, held.set_by), (history_key(2, 2), Some(fresh.id)));
    let used = w
        .devices
        .request(w.alice, asked.request.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        used.ended.map(|ending| ending.how),
        Some(StartOverEnd::Used)
    );
}

#[tokio::test]
async fn a_start_over_still_takes_a_recent_password() {
    let w = world();
    let t = now();
    w.laptop(t).await;
    let fresh = w.device(2, t).await;
    w.ask.execute(&fresh.bearer, t).await.unwrap();
    let later = t + START_OVER_WAIT;

    let refused = w.set.execute(&fresh.bearer, history_key(2, 2), later).await;

    assert!(
        matches!(refused, Err(ArchiveError::RecentSignInRequired)),
        "{refused:?}"
    );
}

#[tokio::test]
async fn an_approved_devices_replacement_is_immediate_and_ends_the_open_request() {
    let w = world();
    let t = now();
    let laptop = w.laptop(t).await;
    let fresh = w.device(2, t).await;
    let asked = w.ask.execute(&fresh.bearer, t).await.unwrap();

    w.set
        .execute(&laptop.bearer, history_key(2, 2), t)
        .await
        .unwrap();

    assert_eq!(w.held().await.set_by, Some(laptop.id));
    assert_eq!(
        w.sent().last(),
        Some(&SentTrust::StartOverCancelled {
            owner: w.alice,
            to: vec![laptop.bearer.session, fresh.bearer.session],
            request: asked.request.id,
            reason: StartOverEnd::Superseded,
        })
    );
    let read = w.load.execute(&fresh.bearer).await.unwrap();
    assert_eq!(
        read.request.ended.map(|ended| ended.how),
        Some(StartOverEnd::Superseded),
        "the asker reads how it ended"
    );
}

#[tokio::test]
async fn revoking_the_asker_cancels_its_request_and_tells_the_approved_devices() {
    let w = world();
    let t = now();
    let laptop = w.laptop(t).await;
    let fresh = w.device(2, t).await;
    let asked = w.ask.execute(&fresh.bearer, t).await.unwrap();

    w.revoke.execute(&laptop.bearer, fresh.id, t).await.unwrap();

    assert_eq!(
        w.sent().last(),
        Some(&SentTrust::StartOverCancelled {
            owner: w.alice,
            to: vec![laptop.bearer.session],
            request: asked.request.id,
            reason: StartOverEnd::Revoked,
        })
    );
    assert_eq!(w.devices.open_of(w.alice).await.unwrap(), None);
}

#[tokio::test]
async fn a_device_not_approved_revokes_no_approved_device_but_may_revoke_itself() {
    let w = world();
    let t = now();
    let laptop = w.laptop(t).await;
    let fresh = w.device(2, t).await;

    let refused = w.revoke.execute(&fresh.bearer, laptop.id, t).await;
    let laptop_still: Option<Session> = w.sessions.find(laptop.bearer.session).await.unwrap();
    w.revoke.execute(&fresh.bearer, fresh.id, t).await.unwrap();

    assert!(
        matches!(
            refused,
            Err(KeyDirectoryError::ApprovalRequired(ApprovalRequired))
        ),
        "{refused:?}"
    );
    assert!(laptop_still.unwrap().is_live(t), "nothing signed out");
    assert_eq!(
        w.sessions.reason(fresh.bearer.session),
        Some(RevokedReason::DeviceRevoked)
    );
}

#[tokio::test]
async fn the_asker_reads_how_its_request_ended_and_the_approved_devices_see_none_open() {
    let w = world();
    let t = now();
    let laptop = w.laptop(t).await;
    let fresh = w.device(2, t).await;
    let asked = w.ask.execute(&fresh.bearer, t).await.unwrap();
    w.end
        .execute(&laptop.bearer, asked.request.id, t)
        .await
        .unwrap();

    let by_the_asker = w.load.execute(&fresh.bearer).await.unwrap();
    let by_the_laptop = w.load.execute(&laptop.bearer).await;

    assert_eq!(by_the_asker.request.id, asked.request.id);
    assert_eq!(
        by_the_asker.request.ended.map(|ended| ended.how),
        Some(StartOverEnd::Cancelled)
    );
    assert!(
        matches!(
            by_the_laptop,
            Err(KeyDirectoryError::StartOver(StartOverRefusal::NotFound))
        ),
        "{by_the_laptop:?}"
    );
}

#[tokio::test]
async fn approving_the_asker_with_a_code_ends_its_request_and_tells_both_sides() {
    let w = world();
    let t = now();
    let laptop = w.laptop(t).await;
    let fresh = w.device(2, t).await;
    let asked = w.ask.execute(&fresh.bearer, t).await.unwrap();
    let signature = plain_signature(
        &DeviceRootKey::parse(&[1; 32]).unwrap(),
        &approval_bytes(&actor(), fresh.id, &DeviceRootKey::parse(&[2; 32]).unwrap()),
    );

    w.approve
        .execute(&laptop.bearer, fresh.id, ApprovalBy::Device, signature)
        .await
        .unwrap();

    assert_eq!(
        w.sent().last(),
        Some(&SentTrust::StartOverCancelled {
            owner: w.alice,
            to: vec![laptop.bearer.session, fresh.bearer.session],
            request: asked.request.id,
            reason: StartOverEnd::Approved,
        })
    );
    assert_eq!(w.devices.open_of(w.alice).await.unwrap(), None);
}

#[tokio::test]
async fn requests_that_ended_are_swept_a_week_after_they_ended() {
    let w = world();
    let t = now();
    let laptop = w.laptop(t).await;
    let fresh = w.device(2, t).await;
    let asked = w.ask.execute(&fresh.bearer, t).await.unwrap();
    w.end
        .execute(&laptop.bearer, asked.request.id, t)
        .await
        .unwrap();

    let within_the_week = w.sweep.execute(t + Duration::days(6)).await.unwrap();
    let past_it = w.sweep.execute(t + Duration::days(8)).await.unwrap();

    assert_eq!((within_the_week, past_it), (0, 1));
    assert_eq!(
        w.devices.request(w.alice, asked.request.id).await.unwrap(),
        None
    );
}

/// Cancels the open request just before the first write, as an approved device's cancel landing
/// between the reads and the write would.
struct CancelledMeanwhile {
    archive: Arc<InMemoryArchive>,
    devices: Arc<InMemoryKeyDirectory>,
    canceller: Mutex<Option<DeviceId>>,
}

#[async_trait::async_trait]
impl HistoryKeys for CancelledMeanwhile {
    async fn current(&self, owner: UserId) -> Result<Option<HeldHistoryKey>, ArchiveStoreError> {
        self.archive.current(owner).await
    }

    async fn replace(
        &self,
        owner: UserId,
        key: &HistoryKey,
        set_by: DeviceId,
        now: OffsetDateTime,
    ) -> Result<KeyReplace, ArchiveStoreError> {
        let canceller = self.canceller.lock().unwrap().take();
        if let Some(canceller) = canceller {
            let open = self.devices.open_of(owner).await.unwrap().unwrap();
            let ended = self
                .devices
                .end(owner, open.id, canceller, StartOverEnd::Cancelled, now)
                .await
                .unwrap();
            assert!(matches!(ended, StartOverEnded::Ended(_)), "{ended:?}");
        }
        self.archive.replace(owner, key, set_by, now).await
    }
}

#[tokio::test]
async fn a_start_over_cancelled_while_it_is_written_is_decided_again_and_refused() {
    let mut meanwhile = None;
    let w = world_keyed_by(|archive, devices| {
        let keys = Arc::new(CancelledMeanwhile {
            archive,
            devices,
            canceller: Mutex::new(None),
        });
        meanwhile = Some(keys.clone());
        keys
    });
    let t = now();
    let laptop = w.laptop(t).await;
    let fresh = w.device(2, t).await;
    w.ask.execute(&fresh.bearer, t).await.unwrap();
    *meanwhile.unwrap().canceller.lock().unwrap() = Some(laptop.id);
    let later = t + START_OVER_WAIT;

    let refused = w
        .set
        .execute(&w.typed_at(&fresh, later), history_key(2, 2), later)
        .await;

    assert!(
        matches!(
            refused,
            Err(ArchiveError::StartOver(StartOverRefusal::Required))
        ),
        "{refused:?}"
    );
    assert_eq!(w.held().await.key, history_key(1, 1));
}

#[tokio::test]
async fn an_unnamed_session_neither_reads_nor_ends_a_request() {
    let w = world();
    let t = now();
    w.laptop(t).await;
    let unnamed = Bearer {
        user: w.alice,
        session: w.sessions.live_at(w.alice, t),
        authenticated_at: t,
    };

    let read = w.load.execute(&unnamed).await;
    let ended = w
        .end
        .execute(&unnamed, StartOverRequestId::generate(), t)
        .await;

    for refused in [read.map(|_| ()), ended] {
        assert!(
            matches!(refused, Err(KeyDirectoryError::DeviceRequired(_))),
            "{refused:?}"
        );
    }
}
