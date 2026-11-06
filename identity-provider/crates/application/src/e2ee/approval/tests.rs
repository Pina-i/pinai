use std::sync::Mutex;

use domain::auth::testing::InMemorySessions;
use domain::e2ee::Approval;
use domain::e2ee::testing::{
    InMemoryApprovalRequests, InMemoryArchive, InMemoryKeyDirectory, PlainEd25519Verifier,
    RecordingDeviceTrustNotifier, SentTrust, plain_signature,
};
use domain::e2ee::{
    ApprovalPublicKey, Approver, Attestation, CheckedApproval, DeviceLabel, DeviceRootKey,
    DeviceTrust, HistoryCheckValue, HistoryGeneration, HistoryKey, HistorySalt, HpkeKeyWrite,
    KeyPackages, KeyStoreError, approval_bytes,
};
use domain::identity::Account;
use domain::identity::testing::{InMemoryAccounts, account};
use time::Duration;

use super::*;
use crate::e2ee::{ListDevices, RevokeDevice};

struct World {
    alice: Account,
    bob: Account,
    sessions: Arc<InMemorySessions>,
    devices: Arc<InMemoryKeyDirectory>,
    archive: Arc<InMemoryArchive>,
    notifier: Arc<RecordingDeviceTrustNotifier>,
    approve: ApproveDevice,
    list_devices: ListDevices,
    open: OpenApprovalRequest,
    list: ListApprovalRequests,
    post: PostApprovalMessage,
    read: ReadApprovalMessages,
    close: CloseApprovalRequest,
    sweep: SweepApprovalRequests,
    revoke: RevokeDevice,
}

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(OffsetDateTime::now_utc().unix_timestamp()).unwrap()
}

fn key(byte: u8) -> DeviceRootKey {
    DeviceRootKey::parse(&[byte; 32]).unwrap()
}

fn history_key(generation: i64, approval_key: u8) -> HistoryKey {
    HistoryKey {
        generation: HistoryGeneration::parse(generation).unwrap(),
        salt: HistorySalt::parse(&[1; 16]).unwrap(),
        check_value: HistoryCheckValue::parse(&[1; 32]).unwrap(),
        approval_public_key: ApprovalPublicKey::parse(&[approval_key; 32]).unwrap(),
    }
}

fn body(byte: u8) -> ApprovalMessageBody {
    ApprovalMessageBody::parse(vec![byte; 32]).unwrap()
}

fn seq(raw: i64) -> MessageSeq {
    MessageSeq::parse(raw).unwrap()
}

fn world_with(
    approvals: impl FnOnce(Arc<InMemoryKeyDirectory>) -> Arc<dyn DeviceApprovals>,
) -> World {
    let (alice, bob) = (account("alice"), account("bob"));
    let accounts = Arc::new(InMemoryAccounts::with([alice.clone(), bob.clone()]));
    let sessions = Arc::new(InMemorySessions::default());
    let archive = Arc::new(InMemoryArchive::default());
    let requests = Arc::new(InMemoryApprovalRequests::default());
    let devices =
        Arc::new(InMemoryKeyDirectory::keyed_by(archive.clone()).relaying(requests.clone()));
    let notifier = Arc::new(RecordingDeviceTrustNotifier::default());
    World {
        approve: ApproveDevice::new(
            accounts,
            sessions.clone(),
            devices.clone(),
            archive.clone(),
            approvals(devices.clone()),
            Arc::new(PlainEd25519Verifier),
            notifier.clone(),
        ),
        list_devices: ListDevices::new(devices.clone(), devices.clone(), sessions.clone()),
        open: OpenApprovalRequest::new(
            sessions.clone(),
            devices.clone(),
            requests.clone(),
            notifier.clone(),
        ),
        list: ListApprovalRequests::new(sessions.clone(), devices.clone(), requests.clone()),
        post: PostApprovalMessage::new(
            sessions.clone(),
            devices.clone(),
            requests.clone(),
            notifier.clone(),
        ),
        read: ReadApprovalMessages::new(sessions.clone(), devices.clone(), requests.clone()),
        close: CloseApprovalRequest::new(
            sessions.clone(),
            devices.clone(),
            requests.clone(),
            notifier.clone(),
        ),
        sweep: SweepApprovalRequests::new(requests.clone()),
        revoke: RevokeDevice::new(
            devices.clone(),
            sessions.clone(),
            devices.clone(),
            Arc::new(domain::auth::testing::RecordingSessionNotifier::default()),
            notifier.clone(),
        ),
        alice,
        bob,
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
    /// A device of `who`'s, its root key made of `root`s, named "Firefox on Linux".
    async fn device(&self, who: &Account, root: u8) -> DeviceId {
        let id = DeviceId::generate();
        let attestation = Attestation {
            root_key: key(root),
            signature: vec![1; 64],
            kid: "key-1".to_owned(),
            issued_at: now(),
            expires_at: now() + Duration::days(365),
        };
        let label = DeviceLabel {
            name: "Firefox on Linux".to_owned(),
            kind: domain::e2ee::DeviceKind::Laptop,
        };
        self.devices
            .attest(who.id, id, &label, None, &attestation, &HpkeKeyWrite::Clear)
            .await
            .unwrap();
        id
    }

    /// A session of `who`'s, naming `device` when given.
    async fn session(&self, who: &Account, device: Option<DeviceId>) -> Bearer {
        let session = self.sessions.live_at(who.id, now());
        if let Some(device) = device {
            self.sessions
                .link(who.id, session, device, now())
                .await
                .unwrap();
        }
        Bearer {
            user: who.id,
            session,
            authenticated_at: now(),
        }
    }

    /// A new device of `who`'s, its root key made of `root`s, and a session naming it.
    async fn on_a_device(&self, who: &Account, root: u8) -> (DeviceId, Bearer) {
        let device = self.device(who, root).await;
        (device, self.session(who, Some(device)).await)
    }

    /// Root key `signer`'s signature over `device`'s root key, made of `root`s.
    fn signed(&self, signer: u8, device: DeviceId, root: u8) -> Ed25519Signature {
        plain_signature(
            &key(signer),
            &approval_bytes(&self.alice.actor_uri, device, &key(root)),
        )
    }

    async fn approvals_of(&self, device: DeviceId) -> Vec<Approval> {
        self.list_devices
            .execute(self.alice.id, now())
            .await
            .unwrap()
            .into_iter()
            .find(|listed| listed.device.id == device)
            .unwrap()
            .approvals
    }

    async fn opened(&self, bearer: &Bearer) -> ApprovalRequest {
        self.open.execute(bearer, now()).await.unwrap()
    }

    fn sent(&self) -> Vec<SentTrust> {
        self.notifier.sent()
    }
}

#[tokio::test]
async fn a_device_approves_another_and_the_account_hears_of_it_once() {
    let w = world();
    let (laptop, on_laptop) = w.on_a_device(&w.alice, 1).await;
    let phone = w.device(&w.alice, 2).await;
    let signature = w.signed(1, phone, 2);

    w.approve
        .execute(&on_laptop, phone, ApprovalBy::Device, signature.clone())
        .await
        .unwrap();
    w.approve
        .execute(&on_laptop, phone, ApprovalBy::Device, signature.clone())
        .await
        .unwrap();

    let approvals = w.approvals_of(phone).await;
    assert_eq!(approvals.len(), 1);
    assert_eq!(
        (
            approvals[0].approver,
            &approvals[0].root_key,
            &approvals[0].signature
        ),
        (Approver::Device(laptop), &key(2), &signature)
    );
    assert_eq!(w.approvals_of(laptop).await, vec![]);
    assert_eq!(
        w.sent(),
        vec![SentTrust::Approved {
            owner: w.alice.id,
            device: phone
        }]
    );
}

#[tokio::test]
async fn the_passphrase_approves_the_device_it_is_typed_on() {
    let w = world();
    let (laptop, on_laptop) = w.on_a_device(&w.alice, 1).await;
    let first = history_key(1, 40);
    w.archive
        .replace(w.alice.id, &first, laptop, time::OffsetDateTime::now_utc())
        .await
        .unwrap();
    let signature = w.signed(40, laptop, 1);

    w.approve
        .execute(
            &on_laptop,
            laptop,
            ApprovalBy::Passphrase(first.generation),
            signature,
        )
        .await
        .unwrap();

    let approvals = w.approvals_of(laptop).await;
    assert_eq!(
        approvals.iter().map(|a| a.approver).collect::<Vec<_>>(),
        vec![Approver::Passphrase(first.generation)]
    );
    assert_eq!(
        w.sent(),
        vec![SentTrust::Approved {
            owner: w.alice.id,
            device: laptop
        }]
    );
}

#[tokio::test]
async fn approving_takes_a_session_that_named_its_unrevoked_device() {
    let w = world();
    let (laptop, on_laptop) = w.on_a_device(&w.alice, 1).await;
    let phone = w.device(&w.alice, 2).await;
    let unnamed = w.session(&w.alice, None).await;
    let signature = w.signed(1, phone, 2);

    let from_unnamed = w
        .approve
        .execute(&unnamed, phone, ApprovalBy::Device, signature.clone())
        .await;
    w.devices
        .revoke(
            w.alice.id,
            laptop,
            Some(laptop),
            time::OffsetDateTime::now_utc(),
        )
        .await
        .unwrap();
    let from_revoked = w
        .approve
        .execute(&on_laptop, phone, ApprovalBy::Device, signature)
        .await;

    assert!(matches!(
        from_unnamed,
        Err(KeyDirectoryError::DeviceRequired(_))
    ));
    assert!(matches!(
        from_revoked,
        Err(KeyDirectoryError::DeviceRevoked)
    ));
    assert_eq!(w.approvals_of(phone).await, vec![]);
    assert_eq!(w.sent(), vec![]);
}

#[tokio::test]
async fn a_refused_approval_stores_nothing_and_tells_nobody() {
    let w = world();
    let (laptop, on_laptop) = w.on_a_device(&w.alice, 1).await;
    let phone = w.device(&w.alice, 2).await;
    let bobs = w.device(&w.bob, 3).await;

    let forged = w
        .approve
        .execute(&on_laptop, phone, ApprovalBy::Device, w.signed(9, phone, 2))
        .await;
    let anothers = w
        .approve
        .execute(&on_laptop, bobs, ApprovalBy::Device, w.signed(1, bobs, 3))
        .await;
    let no_key_yet = w
        .approve
        .execute(
            &on_laptop,
            laptop,
            ApprovalBy::Passphrase(HistoryGeneration::FIRST),
            w.signed(40, laptop, 1),
        )
        .await;

    assert!(matches!(forged, Err(KeyDirectoryError::ApprovalUnsigned)));
    assert!(matches!(anothers, Err(KeyDirectoryError::DeviceNotFound)));
    assert!(matches!(
        no_key_yet,
        Err(KeyDirectoryError::StaleHistoryKey(_))
    ));
    assert_eq!(w.approvals_of(phone).await, vec![]);
    assert_eq!(w.approvals_of(laptop).await, vec![]);
    assert_eq!(w.sent(), vec![]);
}

/// Revokes the approved device the first time an approval is written, as a revoke landing between
/// the reads and the write would, and answers that the write found it changed.
struct RevokedMeanwhile {
    devices: Arc<InMemoryKeyDirectory>,
    revoked: Mutex<bool>,
}

#[async_trait::async_trait]
impl DeviceApprovals for RevokedMeanwhile {
    async fn approve(
        &self,
        owner: UserId,
        approval: &CheckedApproval,
    ) -> Result<Approve, KeyStoreError> {
        if !std::mem::replace(&mut *self.revoked.lock().unwrap(), true) {
            self.devices
                .revoke(
                    owner,
                    approval.device(),
                    Some(approval.device()),
                    time::OffsetDateTime::now_utc(),
                )
                .await?;
            return Ok(Approve::Stale);
        }
        self.devices.approve(owner, approval).await
    }

    async fn of_owner(&self, owner: UserId) -> Result<Vec<Approval>, KeyStoreError> {
        self.devices.of_owner(owner).await
    }

    async fn trust(&self, owner: UserId) -> Result<DeviceTrust, KeyStoreError> {
        self.devices.trust(owner).await
    }
}

#[tokio::test]
async fn an_approval_whose_device_changed_meanwhile_is_decided_again() {
    let w = world_with(|devices| {
        Arc::new(RevokedMeanwhile {
            devices,
            revoked: Mutex::new(false),
        })
    });
    let (_, on_laptop) = w.on_a_device(&w.alice, 1).await;
    let phone = w.device(&w.alice, 2).await;

    let approved = w
        .approve
        .execute(&on_laptop, phone, ApprovalBy::Device, w.signed(1, phone, 2))
        .await;

    assert!(matches!(approved, Err(KeyDirectoryError::DeviceRevoked)));
    assert_eq!(w.sent(), vec![]);
}

#[tokio::test]
async fn opening_a_request_tells_the_accounts_other_devices() {
    let w = world();
    let (laptop, on_laptop) = w.on_a_device(&w.alice, 1).await;
    let (_, on_phone) = w.on_a_device(&w.alice, 2).await;
    let _unnamed = w.session(&w.alice, None).await;
    w.on_a_device(&w.bob, 3).await;

    let request = w.opened(&on_laptop).await;

    assert_eq!(
        (request.owner, request.device, request.approver),
        (w.alice.id, laptop, None)
    );
    assert_eq!(request.expires_at, now() + Duration::minutes(10));
    assert_eq!(
        w.sent(),
        vec![SentTrust::Requested {
            owner: w.alice.id,
            to: vec![on_phone.session],
            request: request.id,
            device: laptop,
            display_name: "Firefox on Linux".to_owned(),
        }]
    );
    assert_eq!(
        w.list.execute(&on_phone, now()).await.unwrap(),
        vec![ListedRequest {
            request,
            display_name: "Firefox on Linux".to_owned()
        }]
    );
}

#[tokio::test]
async fn a_request_takes_a_named_device_with_a_root_key() {
    let w = world();
    let unattested = DeviceId::generate();
    w.devices
        .stash(w.alice.id, unattested, &DeviceLabel::unknown(), false, &[])
        .await
        .unwrap();
    let on_unattested = w.session(&w.alice, Some(unattested)).await;
    let unnamed = w.session(&w.alice, None).await;

    let without_a_root_key = w.open.execute(&on_unattested, now()).await;
    let from_unnamed = w.open.execute(&unnamed, now()).await;
    let listed_unnamed = w.list.execute(&unnamed, now()).await;

    assert!(matches!(
        without_a_root_key,
        Err(KeyDirectoryError::NoRootKey)
    ));
    assert!(matches!(
        from_unnamed,
        Err(KeyDirectoryError::DeviceRequired(_))
    ));
    assert!(matches!(
        listed_unnamed,
        Err(KeyDirectoryError::DeviceRequired(_))
    ));
    assert_eq!(w.sent(), vec![]);
}

#[tokio::test]
async fn a_new_request_closes_the_devices_open_one_and_says_so() {
    let w = world();
    let (_, on_laptop) = w.on_a_device(&w.alice, 1).await;
    let (_, on_phone) = w.on_a_device(&w.alice, 2).await;
    let first = w.opened(&on_laptop).await;

    let second = w.opened(&on_laptop).await;

    assert_eq!(
        w.sent()[1],
        SentTrust::Closed {
            owner: w.alice.id,
            to: vec![on_laptop.session, on_phone.session],
            request: first.id,
        }
    );
    assert!(matches!(w.sent()[2], SentTrust::Requested { request, .. } if request == second.id));
    let listed: Vec<_> = w
        .list
        .execute(&on_phone, now())
        .await
        .unwrap()
        .into_iter()
        .map(|listed| listed.request.id)
        .collect();
    assert_eq!(listed, vec![second.id]);
}

#[tokio::test]
async fn an_account_opens_ten_requests_an_hour() {
    let w = world();
    let (_, on_laptop) = w.on_a_device(&w.alice, 1).await;
    for _ in 0..10 {
        w.opened(&on_laptop).await;
    }

    let eleventh = w.open.execute(&on_laptop, now()).await;
    let an_hour_on = w
        .open
        .execute(&on_laptop, now() + Duration::minutes(61))
        .await;

    assert!(matches!(
        eleventh,
        Err(KeyDirectoryError::Request(RequestRefusal::TooMany))
    ));
    assert!(an_hour_on.is_ok());
}

#[tokio::test]
async fn a_relayed_handshake_reaches_each_side_and_binds_to_the_first_answer() {
    let w = world();
    let (laptop, on_laptop) = w.on_a_device(&w.alice, 1).await;
    let (phone, on_phone) = w.on_a_device(&w.alice, 2).await;
    let (_, on_tablet) = w.on_a_device(&w.alice, 3).await;
    let request = w.opened(&on_laptop).await;

    let asked = w
        .post
        .execute(&on_laptop, request.id, body(1), now())
        .await
        .unwrap();
    let seen_by_the_phone = w
        .read
        .execute(&on_phone, request.id, MessageSeq::START, now())
        .await
        .unwrap();
    let answered = w
        .post
        .execute(&on_phone, request.id, body(2), now())
        .await
        .unwrap();
    let tablet_posts = w.post.execute(&on_tablet, request.id, body(3), now()).await;
    let tablet_reads = w
        .read
        .execute(&on_tablet, request.id, MessageSeq::START, now())
        .await;
    let seen_by_the_laptop = w
        .read
        .execute(&on_laptop, request.id, MessageSeq::START, now())
        .await
        .unwrap();
    let confirmed = w
        .post
        .execute(&on_laptop, request.id, body(4), now())
        .await
        .unwrap();

    assert_eq!((asked, answered, confirmed), (seq(1), seq(2), seq(3)));
    assert_eq!(
        seen_by_the_phone
            .iter()
            .map(|m| (m.seq, m.from, m.body.clone()))
            .collect::<Vec<_>>(),
        vec![(seq(1), laptop, body(1))]
    );
    assert_eq!(
        seen_by_the_laptop
            .iter()
            .map(|m| (m.seq, m.from))
            .collect::<Vec<_>>(),
        vec![(seq(2), phone)]
    );
    assert!(matches!(
        tablet_posts,
        Err(KeyDirectoryError::Request(RequestRefusal::Taken))
    ));
    assert!(matches!(
        tablet_reads,
        Err(KeyDirectoryError::Request(RequestRefusal::Taken))
    ));
    let messages: Vec<_> = w
        .sent()
        .into_iter()
        .filter_map(|sent| match sent {
            SentTrust::Message { to, seq, .. } => Some((seq, to)),
            _ => None,
        })
        .collect();
    assert_eq!(
        messages,
        vec![
            (seq(1), vec![on_phone.session, on_tablet.session]),
            (seq(2), vec![on_laptop.session]),
            (seq(3), vec![on_phone.session]),
        ]
    );
    assert!(
        w.sent().contains(&SentTrust::Closed {
            owner: w.alice.id,
            to: vec![on_tablet.session],
            request: request.id,
        }),
        "the tablet's prompt goes once the phone answers"
    );
}

#[tokio::test]
async fn either_side_ends_the_request_and_both_hear_of_it() {
    let w = world();
    let (_, on_laptop) = w.on_a_device(&w.alice, 1).await;
    let (_, on_phone) = w.on_a_device(&w.alice, 2).await;
    let (_, on_tablet) = w.on_a_device(&w.alice, 3).await;
    let request = w.opened(&on_laptop).await;
    w.post
        .execute(&on_phone, request.id, body(1), now())
        .await
        .unwrap();

    let by_a_third = w.close.execute(&on_tablet, request.id, now()).await;
    w.close.execute(&on_phone, request.id, now()).await.unwrap();
    let again = w.close.execute(&on_laptop, request.id, now()).await;
    let posted_after = w.post.execute(&on_laptop, request.id, body(2), now()).await;

    assert!(matches!(
        by_a_third,
        Err(KeyDirectoryError::Request(RequestRefusal::Taken))
    ));
    assert!(matches!(
        again,
        Err(KeyDirectoryError::Request(RequestRefusal::Ended))
    ));
    assert!(matches!(
        posted_after,
        Err(KeyDirectoryError::Request(RequestRefusal::Ended))
    ));
    assert_eq!(
        w.sent().last(),
        Some(&SentTrust::Closed {
            owner: w.alice.id,
            to: vec![on_laptop.session, on_phone.session],
            request: request.id,
        })
    );
    assert_eq!(w.list.execute(&on_tablet, now()).await.unwrap(), vec![]);
}

#[tokio::test]
async fn a_request_past_its_ten_minutes_has_ended() {
    let w = world();
    let (_, on_laptop) = w.on_a_device(&w.alice, 1).await;
    let (_, on_phone) = w.on_a_device(&w.alice, 2).await;
    let request = w.opened(&on_laptop).await;
    let later = request.expires_at;

    let posted = w.post.execute(&on_phone, request.id, body(1), later).await;
    let read = w
        .read
        .execute(&on_phone, request.id, MessageSeq::START, later)
        .await;
    let closed = w.close.execute(&on_laptop, request.id, later).await;

    for refused in [posted.map(|_| ()), read.map(|_| ()), closed] {
        assert!(matches!(
            refused,
            Err(KeyDirectoryError::Request(RequestRefusal::Ended))
        ));
    }
    assert_eq!(w.list.execute(&on_phone, later).await.unwrap(), vec![]);
}

#[tokio::test]
async fn another_accounts_request_is_not_found() {
    let w = world();
    let (_, on_laptop) = w.on_a_device(&w.alice, 1).await;
    let (_, bobs) = w.on_a_device(&w.bob, 2).await;
    let request = w.opened(&on_laptop).await;

    let read = w
        .read
        .execute(&bobs, request.id, MessageSeq::START, now())
        .await;
    let posted = w.post.execute(&bobs, request.id, body(1), now()).await;
    let closed = w.close.execute(&bobs, request.id, now()).await;

    for refused in [read.map(|_| ()), posted.map(|_| ()), closed] {
        assert!(matches!(
            refused,
            Err(KeyDirectoryError::Request(RequestRefusal::NotFound))
        ));
    }
    assert_eq!(w.list.execute(&bobs, now()).await.unwrap(), vec![]);
}

#[tokio::test]
async fn the_sweep_deletes_the_requests_opened_over_an_hour_ago() {
    let w = world();
    let (_, on_laptop) = w.on_a_device(&w.alice, 1).await;
    let old = w
        .open
        .execute(&on_laptop, now() - Duration::minutes(61))
        .await
        .unwrap();

    let swept = w.sweep.execute(now()).await.unwrap();
    let read = w
        .read
        .execute(&on_laptop, old.id, MessageSeq::START, now())
        .await;

    assert_eq!(swept, 1);
    assert!(matches!(
        read,
        Err(KeyDirectoryError::Request(RequestRefusal::NotFound))
    ));
}

#[tokio::test]
async fn a_device_without_a_root_key_cannot_answer_a_request() {
    let w = world();
    let (_, on_laptop) = w.on_a_device(&w.alice, 1).await;
    let unattested = DeviceId::generate();
    w.devices
        .stash(w.alice.id, unattested, &DeviceLabel::unknown(), false, &[])
        .await
        .unwrap();
    let on_unattested = w.session(&w.alice, Some(unattested)).await;
    let request = w.opened(&on_laptop).await;

    let answered = w
        .post
        .execute(&on_unattested, request.id, body(1), now())
        .await;

    assert!(matches!(
        answered,
        Err(KeyDirectoryError::Request(RequestRefusal::NoRootKey))
    ));
}

#[tokio::test]
async fn the_asking_device_reads_the_last_message_after_the_other_closed() {
    let w = world();
    let (_, on_laptop) = w.on_a_device(&w.alice, 1).await;
    let (phone, on_phone) = w.on_a_device(&w.alice, 2).await;
    let request = w.opened(&on_laptop).await;
    w.post
        .execute(&on_phone, request.id, body(1), now())
        .await
        .unwrap();
    w.close.execute(&on_phone, request.id, now()).await.unwrap();

    let read = w
        .read
        .execute(&on_laptop, request.id, MessageSeq::START, now())
        .await
        .unwrap();

    assert_eq!(
        read.iter().map(|m| (m.seq, m.from)).collect::<Vec<_>>(),
        vec![(seq(1), phone)]
    );
}

#[tokio::test]
async fn revoking_a_device_ends_its_requests_and_tells_the_other_side() {
    let w = world();
    let (laptop, on_laptop) = w.on_a_device(&w.alice, 1).await;
    let (_, on_phone) = w.on_a_device(&w.alice, 2).await;
    let request = w.opened(&on_laptop).await;
    w.post
        .execute(&on_phone, request.id, body(1), now())
        .await
        .unwrap();

    w.revoke.execute(&on_phone, laptop, now()).await.unwrap();

    assert_eq!(
        w.sent().last(),
        Some(&SentTrust::Closed {
            owner: w.alice.id,
            to: vec![on_phone.session],
            request: request.id,
        })
    );
    assert_eq!(w.list.execute(&on_phone, now()).await.unwrap(), vec![]);
}

/// Approvals as a read straddling a rotation sees them: the phone's, of a root key before its
/// current one.
struct ApprovalsOfAnOldKey {
    phone: DeviceId,
    laptop: DeviceId,
}

#[async_trait::async_trait]
impl DeviceApprovals for ApprovalsOfAnOldKey {
    async fn approve(&self, _: UserId, _: &CheckedApproval) -> Result<Approve, KeyStoreError> {
        unreachable!("only listed")
    }

    async fn of_owner(&self, _: UserId) -> Result<Vec<Approval>, KeyStoreError> {
        Ok(vec![Approval {
            device: self.phone,
            root_key: key(9),
            approver: Approver::Device(self.laptop),
            signature: plain_signature(&key(1), b"anything"),
            created_at: now(),
        }])
    }

    async fn trust(&self, _: UserId) -> Result<DeviceTrust, KeyStoreError> {
        unreachable!("only listed")
    }
}

#[tokio::test]
async fn an_approval_of_a_root_key_the_device_no_longer_holds_is_not_listed() {
    let w = world();
    let laptop = w.device(&w.alice, 1).await;
    let phone = w.device(&w.alice, 2).await;
    let list = ListDevices::new(
        w.devices.clone(),
        Arc::new(ApprovalsOfAnOldKey { phone, laptop }),
        w.sessions.clone(),
    );

    let listed = list.execute(w.alice.id, now()).await.unwrap();

    assert!(listed.iter().all(|device| device.approvals.is_empty()));
}

/// Every write finds the devices changed.
struct AlwaysStale;

#[async_trait::async_trait]
impl DeviceApprovals for AlwaysStale {
    async fn approve(&self, _: UserId, _: &CheckedApproval) -> Result<Approve, KeyStoreError> {
        Ok(Approve::Stale)
    }

    async fn of_owner(&self, _: UserId) -> Result<Vec<Approval>, KeyStoreError> {
        Ok(Vec::new())
    }

    async fn trust(&self, _: UserId) -> Result<DeviceTrust, KeyStoreError> {
        Ok(DeviceTrust::default())
    }
}

#[tokio::test]
async fn an_approval_whose_devices_keep_changing_gives_up_after_three_tries() {
    let w = world_with(|_| Arc::new(AlwaysStale));
    let (_, on_laptop) = w.on_a_device(&w.alice, 1).await;
    let phone = w.device(&w.alice, 2).await;

    let approved = w
        .approve
        .execute(&on_laptop, phone, ApprovalBy::Device, w.signed(1, phone, 2))
        .await;

    assert!(matches!(approved, Err(KeyDirectoryError::Unexpected(_))));
    assert_eq!(w.sent(), vec![]);
}

/// Revokes the acting device as the write starts, as a revoke landing between the read and the
/// write would, and answers that the write found it so.
struct RevokedAsItWrites {
    devices: Arc<InMemoryKeyDirectory>,
    requests: InMemoryApprovalRequests,
}

#[async_trait::async_trait]
impl ApprovalRequests for RevokedAsItWrites {
    async fn open(&self, request: &ApprovalRequest) -> Result<Opened, KeyStoreError> {
        self.devices
            .revoke(
                request.owner,
                request.device,
                Some(request.device),
                time::OffsetDateTime::now_utc(),
            )
            .await?;
        Ok(Opened::Stale)
    }

    async fn open_of(
        &self,
        owner: UserId,
        now: OffsetDateTime,
    ) -> Result<Vec<ApprovalRequest>, KeyStoreError> {
        self.requests.open_of(owner, now).await
    }

    async fn post(
        &self,
        owner: UserId,
        _: ApprovalRequestId,
        from: &Device,
        _: &ApprovalMessageBody,
        _: OffsetDateTime,
    ) -> Result<Post, KeyStoreError> {
        self.devices
            .revoke(
                owner,
                from.id,
                Some(from.id),
                time::OffsetDateTime::now_utc(),
            )
            .await?;
        Ok(Post::Stale)
    }

    async fn read(
        &self,
        owner: UserId,
        id: ApprovalRequestId,
        reader: DeviceId,
        after: MessageSeq,
        now: OffsetDateTime,
    ) -> Result<Read, KeyStoreError> {
        self.requests.read(owner, id, reader, after, now).await
    }

    async fn close(
        &self,
        owner: UserId,
        id: ApprovalRequestId,
        by: DeviceId,
        now: OffsetDateTime,
    ) -> Result<Close, KeyStoreError> {
        self.requests.close(owner, id, by, now).await
    }

    async fn delete_opened_before(&self, cutoff: OffsetDateTime) -> Result<usize, KeyStoreError> {
        self.requests.delete_opened_before(cutoff).await
    }
}

#[tokio::test]
async fn a_device_revoked_as_it_asks_or_answers_is_refused_and_nobody_is_told() {
    let w = world();
    let (_, on_laptop) = w.on_a_device(&w.alice, 1).await;
    let (_, on_phone) = w.on_a_device(&w.alice, 2).await;
    let request = w.opened(&on_laptop).await;
    let racing = Arc::new(RevokedAsItWrites {
        devices: w.devices.clone(),
        requests: InMemoryApprovalRequests::default(),
    });
    let open = OpenApprovalRequest::new(
        w.sessions.clone(),
        w.devices.clone(),
        racing.clone(),
        w.notifier.clone(),
    );
    let post = PostApprovalMessage::new(
        w.sessions.clone(),
        w.devices.clone(),
        racing,
        w.notifier.clone(),
    );
    let told = w.sent().len();

    let opened = open.execute(&on_laptop, now()).await;
    let answered = post.execute(&on_phone, request.id, body(1), now()).await;

    assert!(matches!(opened, Err(KeyDirectoryError::DeviceRevoked)));
    assert!(matches!(answered, Err(KeyDirectoryError::DeviceRevoked)));
    assert_eq!(w.sent().len(), told);
}
