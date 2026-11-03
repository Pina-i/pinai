use std::sync::Mutex;

use domain::auth::SessionKind;
use domain::auth::testing::InMemorySessions;
use domain::e2ee::testing::{
    InMemoryArchive, InMemoryKeyDirectory, PlainEd25519Verifier, RecordingDeviceTrustNotifier,
    SentTrust, hpke_key, plain_signature, sealed_share,
};
use domain::e2ee::{
    ApprovalBy, ApprovalFacts, ApprovalPublicKey, Attestation, CheckedShare, DeviceLabel,
    DeviceRootKey, HistoryCheckValue, HistoryKey, HistorySalt, HpkeKeyWrite, KeyStoreError,
    approval_bytes, may_approve,
};
use domain::identity::Account;
use domain::identity::testing::{InMemoryAccounts, account};
use time::Duration;

use super::*;

struct World {
    alice: Account,
    sessions: Arc<InMemorySessions>,
    devices: Arc<InMemoryKeyDirectory>,
    archive: Arc<InMemoryArchive>,
    notifier: Arc<RecordingDeviceTrustNotifier>,
    share: ShareHistoryKey,
    load: LoadKeyShare,
}

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(OffsetDateTime::now_utc().unix_timestamp()).unwrap()
}

fn key(byte: u8) -> DeviceRootKey {
    DeviceRootKey::parse(&[byte; 32]).unwrap()
}

/// Generation 1, its approval key made of 40s.
fn first() -> HistoryKey {
    HistoryKey {
        generation: HistoryGeneration::FIRST,
        salt: HistorySalt::parse(&[1; 16]).unwrap(),
        check_value: HistoryCheckValue::parse(&[1; 32]).unwrap(),
        approval_public_key: ApprovalPublicKey::parse(&[40; 32]).unwrap(),
    }
}

fn world_with(shares: impl FnOnce(Arc<InMemoryKeyDirectory>) -> Arc<dyn KeyShares>) -> World {
    let alice = account("alice");
    let accounts = Arc::new(InMemoryAccounts::with([alice.clone()]));
    let sessions = Arc::new(InMemorySessions::default());
    let archive = Arc::new(InMemoryArchive::default());
    let devices = Arc::new(InMemoryKeyDirectory::keyed_by(archive.clone()));
    let notifier = Arc::new(RecordingDeviceTrustNotifier::default());
    let shares = shares(devices.clone());
    World {
        share: ShareHistoryKey::new(
            accounts,
            sessions.clone(),
            devices.clone(),
            archive.clone(),
            devices.clone(),
            shares.clone(),
            Arc::new(PlainEd25519Verifier),
            notifier.clone(),
        ),
        load: LoadKeyShare::new(sessions.clone(), devices.clone(), archive.clone(), shares),
        alice,
        sessions,
        devices,
        archive,
        notifier,
    }
}

fn world() -> World {
    world_with(|devices| devices)
}

impl World {
    /// A device of Alice's, its root key and HPKE key made of `root`s.
    async fn device(&self, root: u8) -> DeviceId {
        let id = DeviceId::generate();
        let attestation = Attestation {
            root_key: key(root),
            signature: vec![1; 64],
            kid: "key-1".to_owned(),
            issued_at: now(),
            expires_at: now() + Duration::days(365),
        };
        self.devices
            .attest(
                self.alice.id,
                id,
                &DeviceLabel::unknown(),
                None,
                &attestation,
                &HpkeKeyWrite::Set(hpke_key(root)),
            )
            .await
            .unwrap();
        id
    }

    /// A session of Alice's, naming `device` when given.
    async fn session(&self, device: Option<DeviceId>) -> Bearer {
        let session = self
            .sessions
            .open(self.alice.id, &SessionKind::Browser, now())
            .await
            .unwrap();
        if let Some(device) = device {
            self.sessions.link(session, device, now()).await.unwrap();
        }
        Bearer {
            user: self.alice.id,
            session,
            authenticated_at: now(),
        }
    }

    async fn approve(&self, signer: DeviceId, approved: DeviceId, by: ApprovalBy, with: u8) {
        let signer = self.devices.find(signer).await.unwrap().unwrap();
        let approved_device = self.devices.find(approved).await.unwrap().unwrap();
        let root = &approved_device.attestation.as_ref().unwrap().root_key;
        let current = first();
        let signature = plain_signature(
            &key(with),
            &approval_bytes(&self.alice.actor_uri, approved, root),
        );
        let facts = ApprovalFacts {
            actor: &self.alice.actor_uri,
            signer: &signer,
            approved: Some(&approved_device),
            current: Some(&current),
        };
        let checked = may_approve(approved, by, signature, facts, &PlainEd25519Verifier).unwrap();
        self.devices.approve(self.alice.id, &checked).await.unwrap();
    }

    /// `device` approved by the words typed on it, and holding generation 1.
    async fn holding(&self, device: DeviceId) {
        self.approve(
            device,
            device,
            ApprovalBy::Passphrase(first().generation),
            40,
        )
        .await;
        self.devices
            .hold_history_key(self.alice.id, device, first().generation)
            .await
            .unwrap();
    }

    /// The laptop, which set generation 1 and holds it, and a session naming it.
    async fn laptop(&self) -> (DeviceId, Bearer) {
        let laptop = self.device(1).await;
        self.archive
            .replace(self.alice.id, &first(), laptop)
            .await
            .unwrap();
        self.holding(laptop).await;
        (laptop, self.session(Some(laptop)).await)
    }

    /// Another device holding generation 1, its keys made of `root`s, and a session naming it.
    async fn holder(&self, root: u8) -> (DeviceId, Bearer) {
        let device = self.device(root).await;
        self.holding(device).await;
        (device, self.session(Some(device)).await)
    }

    /// A device `approver` approved, its keys made of `root`s, and a session naming it.
    async fn approved_by(
        &self,
        approver: DeviceId,
        approver_root: u8,
        root: u8,
    ) -> (DeviceId, Bearer) {
        let device = self.device(root).await;
        self.approve(approver, device, ApprovalBy::Device, approver_root)
            .await;
        (device, self.session(Some(device)).await)
    }

    async fn share(
        &self,
        from: &Bearer,
        sender: DeviceId,
        sender_root: u8,
        recipient: DeviceId,
    ) -> Result<(), KeyDirectoryError> {
        let sealed = sealed_share(
            &key(sender_root),
            &self.alice.actor_uri,
            sender,
            recipient,
            first().generation,
            sender_root,
        );
        self.share
            .execute(from, recipient, first().generation, sealed, now())
            .await
    }
}

#[tokio::test]
async fn a_holder_shares_with_an_approved_device_and_its_sessions_alone_hear_of_it() {
    let w = world();
    let (laptop, on_laptop) = w.laptop().await;
    let (phone, on_phone) = w.approved_by(laptop, 1, 2).await;
    w.session(None).await;

    w.share(&on_laptop, laptop, 1, phone).await.unwrap();

    let held = w.load.execute(&on_phone).await.unwrap();
    assert_eq!(
        (held.sender, held.recipient, held.generation),
        (laptop, phone, first().generation)
    );
    assert_eq!(
        held.sealed,
        sealed_share(
            &key(1),
            &w.alice.actor_uri,
            laptop,
            phone,
            first().generation,
            1
        )
    );
    assert_eq!(
        w.notifier.sent(),
        vec![SentTrust::HistoryKeyReady {
            owner: w.alice.id,
            to: vec![on_phone.session],
            device: phone,
        }]
    );
}

#[tokio::test]
async fn a_holder_that_did_not_approve_the_device_shares_nothing_with_it() {
    let w = world();
    let (laptop, _) = w.laptop().await;
    let (tablet, on_tablet) = w.holder(3).await;
    let (phone, on_phone) = w.approved_by(laptop, 1, 2).await;

    let refused = w.share(&on_tablet, tablet, 3, phone).await;

    assert!(matches!(refused, Err(KeyDirectoryError::NotTheApprover)));
    assert!(matches!(
        w.load.execute(&on_phone).await,
        Err(KeyDirectoryError::NoKeyShare)
    ));
    assert_eq!(w.notifier.sent(), vec![]);
}

#[tokio::test]
async fn of_two_devices_that_approved_it_only_the_first_share_is_kept_and_told() {
    let w = world();
    let (laptop, on_laptop) = w.laptop().await;
    let (tablet, on_tablet) = w.holder(3).await;
    let (phone, on_phone) = w.approved_by(laptop, 1, 2).await;
    w.approve(tablet, phone, ApprovalBy::Device, 3).await;

    w.share(&on_laptop, laptop, 1, phone).await.unwrap();
    w.share(&on_tablet, tablet, 3, phone).await.unwrap();
    w.share(&on_laptop, laptop, 1, phone).await.unwrap();

    assert_eq!(w.load.execute(&on_phone).await.unwrap().sender, laptop);
    assert_eq!(w.notifier.sent().len(), 1);
}

#[tokio::test]
async fn sharing_takes_a_session_that_named_its_unrevoked_device() {
    let w = world();
    let (laptop, on_laptop) = w.laptop().await;
    let (phone, _) = w.approved_by(laptop, 1, 2).await;
    let unnamed = w.session(None).await;

    let without_a_device = w.share(&unnamed, laptop, 1, phone).await;
    w.devices.revoke(w.alice.id, laptop).await.unwrap();
    let from_a_revoked = w.share(&on_laptop, laptop, 1, phone).await;

    assert!(matches!(
        without_a_device,
        Err(KeyDirectoryError::DeviceRequired(_))
    ));
    assert!(matches!(
        from_a_revoked,
        Err(KeyDirectoryError::DeviceRevoked)
    ));
    assert_eq!(w.notifier.sent(), vec![]);
}

#[tokio::test]
async fn a_share_to_a_device_nobody_approved_stores_nothing_and_tells_nobody() {
    let w = world();
    let (laptop, on_laptop) = w.laptop().await;
    let phone = w.device(2).await;
    let on_phone = w.session(Some(phone)).await;

    let refused = w.share(&on_laptop, laptop, 1, phone).await;

    assert!(matches!(
        refused,
        Err(KeyDirectoryError::RecipientNotApproved)
    ));
    assert!(matches!(
        w.load.execute(&on_phone).await,
        Err(KeyDirectoryError::NoKeyShare)
    ));
    assert_eq!(w.notifier.sent(), vec![]);
}

/// Has the recipient say it holds the generation the first time a share is written, as a report
/// landing between the reads and the write would, and answers that the write found it changed.
struct ReportedMeanwhile {
    devices: Arc<InMemoryKeyDirectory>,
    reported: Mutex<bool>,
}

#[async_trait::async_trait]
impl KeyShares for ReportedMeanwhile {
    async fn deposit(&self, owner: UserId, share: &CheckedShare) -> Result<Deposit, KeyStoreError> {
        if !std::mem::replace(&mut *self.reported.lock().unwrap(), true) {
            self.devices
                .hold_history_key(owner, share.recipient(), share.generation())
                .await?;
            return Ok(Deposit::Stale);
        }
        self.devices.deposit(owner, share).await
    }

    async fn of_recipient(
        &self,
        owner: UserId,
        recipient: DeviceId,
        generation: HistoryGeneration,
    ) -> Result<Option<KeyShare>, KeyStoreError> {
        self.devices
            .of_recipient(owner, recipient, generation)
            .await
    }
}

#[tokio::test]
async fn a_share_whose_recipient_changed_meanwhile_is_decided_again() {
    let w = world_with(|devices| {
        Arc::new(ReportedMeanwhile {
            devices,
            reported: Mutex::new(false),
        })
    });
    let (laptop, on_laptop) = w.laptop().await;
    let (phone, _) = w.approved_by(laptop, 1, 2).await;

    let shared = w.share(&on_laptop, laptop, 1, phone).await;

    assert!(matches!(shared, Err(KeyDirectoryError::HistoryKeyHeld)));
    assert_eq!(w.notifier.sent(), vec![]);
}

struct AlwaysStale;

#[async_trait::async_trait]
impl KeyShares for AlwaysStale {
    async fn deposit(&self, _: UserId, _: &CheckedShare) -> Result<Deposit, KeyStoreError> {
        Ok(Deposit::Stale)
    }

    async fn of_recipient(
        &self,
        _: UserId,
        _: DeviceId,
        _: HistoryGeneration,
    ) -> Result<Option<KeyShare>, KeyStoreError> {
        Ok(None)
    }
}

#[tokio::test]
async fn a_share_whose_devices_keep_changing_gives_up_after_three_tries() {
    let w = world_with(|_| Arc::new(AlwaysStale));
    let (laptop, on_laptop) = w.laptop().await;
    let (phone, _) = w.approved_by(laptop, 1, 2).await;

    let shared = w.share(&on_laptop, laptop, 1, phone).await;

    assert!(matches!(shared, Err(KeyDirectoryError::Unexpected(_))));
    assert_eq!(w.notifier.sent(), vec![]);
}

#[tokio::test]
async fn a_device_reads_the_share_waiting_for_it_under_the_current_generation() {
    let w = world();
    let unnamed = w.session(None).await;
    let early = w.device(9).await;
    let on_early = w.session(Some(early)).await;
    let before_any_key = w.load.execute(&on_early).await;
    let (laptop, on_laptop) = w.laptop().await;
    let (phone, on_phone) = w.approved_by(laptop, 1, 2).await;
    w.share(&on_laptop, laptop, 1, phone).await.unwrap();

    let the_senders = w.load.execute(&on_laptop).await;
    let without_a_device = w.load.execute(&unnamed).await;
    let waiting = w.load.execute(&on_phone).await;
    w.devices
        .hold_history_key(w.alice.id, phone, first().generation)
        .await
        .unwrap();
    let once_held = w.load.execute(&on_phone).await;

    assert!(matches!(before_any_key, Err(KeyDirectoryError::NoKeyShare)));
    assert!(matches!(the_senders, Err(KeyDirectoryError::NoKeyShare)));
    assert!(matches!(
        without_a_device,
        Err(KeyDirectoryError::DeviceRequired(_))
    ));
    assert_eq!(waiting.unwrap().sender, laptop);
    assert!(matches!(once_held, Err(KeyDirectoryError::NoKeyShare)));
}
