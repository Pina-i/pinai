//! The approval stores in memory, a recording notifier, and the contract every store must satisfy.

use crate::e2ee::{
    ApprovalMessage, ApprovalMessageBody, ApprovalRequest, ApprovalRequests, Approve,
    CheckedApproval, Close, DeviceApprovals, DeviceTrustNotifier, MessageSeq, Opened, Post, Read,
    RequestRefusal, may_open_request, window_start,
};
use crate::{ApprovalRequestId, SessionId};

use super::*;

#[async_trait::async_trait]
impl DeviceApprovals for InMemoryKeyDirectory {
    async fn approve(
        &self,
        owner: UserId,
        approval: &CheckedApproval,
    ) -> Result<Approve, KeyStoreError> {
        if let Approver::Passphrase(generation) = approval.approver() {
            let current = self
                .history
                .as_ref()
                .and_then(|history| history.state.lock().unwrap().generation(owner));
            if check_history_generation(generation, current).is_err() {
                return Ok(Approve::Stale);
            }
        }
        let state = self.state.lock().unwrap();
        let holds = |id: DeviceId, key: &DeviceRootKey| {
            state.devices.iter().any(|device| {
                device.id == id
                    && device.owner == owner
                    && !device.is_revoked()
                    && device
                        .attestation
                        .as_ref()
                        .is_some_and(|held| held.root_key == *key)
            })
        };
        let signer_holds = match (approval.approver(), approval.approver_key()) {
            (Approver::Device(id), Some(key)) => holds(id, key),
            (Approver::Passphrase(_), None) => true,
            _ => false,
        };
        if !signer_holds || !holds(approval.device(), approval.root_key()) {
            return Ok(Approve::Stale);
        }
        let mut approvals = self.approvals.lock().unwrap();
        if approvals.iter().any(|(_, held)| {
            held.device == approval.device() && held.approver == approval.approver()
        }) {
            return Ok(Approve::AlreadyHeld);
        }
        approvals.push((
            owner,
            Approval {
                device: approval.device(),
                root_key: approval.root_key().clone(),
                approver: approval.approver(),
                signature: approval.signature().clone(),
                created_at: OffsetDateTime::now_utc(),
            },
        ));
        Ok(Approve::Recorded)
    }

    async fn of_owner(&self, owner: UserId) -> Result<Vec<Approval>, KeyStoreError> {
        Ok(self
            .approvals
            .lock()
            .unwrap()
            .iter()
            .filter(|(of, _)| *of == owner)
            .map(|(_, approval)| approval.clone())
            .collect())
    }
}

#[derive(Default)]
pub struct InMemoryApprovalRequests {
    state: Mutex<RequestsState>,
}

#[derive(Default)]
struct RequestsState {
    requests: Vec<ApprovalRequest>,
    messages: Vec<(ApprovalRequestId, ApprovalMessage)>,
}

impl RequestsState {
    fn owned(&mut self, owner: UserId, id: ApprovalRequestId) -> Option<&mut ApprovalRequest> {
        self.requests
            .iter_mut()
            .find(|request| request.id == id && request.owner == owner)
    }
}

impl InMemoryApprovalRequests {
    /// What a revoke of `device` does to the requests it asks or answers: the open ones closed.
    pub(super) fn close_for(&self, device: DeviceId, now: OffsetDateTime) -> Vec<ApprovalRequest> {
        let mut state = self.state.lock().unwrap();
        let mut closed = Vec::new();
        for request in state
            .requests
            .iter_mut()
            .filter(|r| r.closed_at.is_none() && (r.device == device || r.approver == Some(device)))
        {
            let was_open = request.is_open(now);
            request.closed_at = Some(now);
            if was_open {
                closed.push(request.clone());
            }
        }
        closed
    }
}

#[async_trait::async_trait]
impl ApprovalRequests for InMemoryApprovalRequests {
    async fn open(&self, request: &ApprovalRequest) -> Result<Opened, KeyStoreError> {
        let now = request.created_at;
        let mut state = self.state.lock().unwrap();
        let opened = state
            .requests
            .iter()
            .filter(|r| r.owner == request.owner && r.created_at > window_start(now))
            .count();
        if may_open_request(opened).is_err() {
            return Ok(Opened::TooMany);
        }
        let mut closed = Vec::new();
        for earlier in state
            .requests
            .iter_mut()
            .filter(|r| r.device == request.device && r.closed_at.is_none())
        {
            let was_open = earlier.is_open(now);
            earlier.closed_at = Some(now);
            if was_open {
                closed.push(earlier.clone());
            }
        }
        state.requests.push(request.clone());
        Ok(Opened::Opened { closed })
    }

    async fn open_of(
        &self,
        owner: UserId,
        now: OffsetDateTime,
    ) -> Result<Vec<ApprovalRequest>, KeyStoreError> {
        let state = self.state.lock().unwrap();
        let mut open: Vec<ApprovalRequest> = state
            .requests
            .iter()
            .filter(|r| r.owner == owner && r.is_open(now))
            .cloned()
            .collect();
        open.sort_by_key(|r| r.created_at);
        Ok(open)
    }

    async fn post(
        &self,
        owner: UserId,
        id: ApprovalRequestId,
        from: &Device,
        body: &ApprovalMessageBody,
        now: OffsetDateTime,
    ) -> Result<Post, KeyStoreError> {
        let mut state = self.state.lock().unwrap();
        let posted = state.messages.iter().filter(|(of, _)| *of == id).count();
        let Some(request) = state.owned(owner, id) else {
            return Ok(Post::Refused(RequestRefusal::NotFound));
        };
        let posting = match request.may_post(from, posted, now) {
            Ok(posting) => posting,
            Err(refusal) => return Ok(Post::Refused(refusal)),
        };
        if posting.binds {
            request.approver = Some(from.id);
        }
        let request = request.clone();
        state.messages.push((
            id,
            ApprovalMessage {
                seq: posting.seq,
                from: from.id,
                body: body.clone(),
                created_at: now,
            },
        ));
        Ok(Post::Posted {
            request,
            seq: posting.seq,
            bound: posting.binds,
        })
    }

    async fn read(
        &self,
        owner: UserId,
        id: ApprovalRequestId,
        reader: DeviceId,
        after: MessageSeq,
        now: OffsetDateTime,
    ) -> Result<Read, KeyStoreError> {
        let mut state = self.state.lock().unwrap();
        let Some(request) = state.owned(owner, id) else {
            return Ok(Read::Refused(RequestRefusal::NotFound));
        };
        if let Err(refusal) = request.may_read(reader, now) {
            return Ok(Read::Refused(refusal));
        }
        Ok(Read::Messages(
            state
                .messages
                .iter()
                .filter(|(of, message)| *of == id && message.seq > after && message.from != reader)
                .map(|(_, message)| message.clone())
                .collect(),
        ))
    }

    async fn close(
        &self,
        owner: UserId,
        id: ApprovalRequestId,
        by: DeviceId,
        now: OffsetDateTime,
    ) -> Result<Close, KeyStoreError> {
        let mut state = self.state.lock().unwrap();
        let Some(request) = state.owned(owner, id) else {
            return Ok(Close::Refused(RequestRefusal::NotFound));
        };
        if let Err(refusal) = request.may_take_part(by, now) {
            return Ok(Close::Refused(refusal));
        }
        request.closed_at = Some(now);
        Ok(Close::Closed(request.clone()))
    }

    async fn delete_opened_before(&self, cutoff: OffsetDateTime) -> Result<usize, KeyStoreError> {
        let mut state = self.state.lock().unwrap();
        let before = state.requests.len();
        state.requests.retain(|r| r.created_at >= cutoff);
        let kept: Vec<ApprovalRequestId> = state.requests.iter().map(|r| r.id).collect();
        state.messages.retain(|(of, _)| kept.contains(of));
        Ok(before - state.requests.len())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SentTrust {
    Approved {
        owner: UserId,
        device: DeviceId,
    },
    Requested {
        owner: UserId,
        to: Vec<SessionId>,
        request: ApprovalRequestId,
        device: DeviceId,
        display_name: String,
    },
    Message {
        owner: UserId,
        to: Vec<SessionId>,
        request: ApprovalRequestId,
        seq: MessageSeq,
    },
    Closed {
        owner: UserId,
        to: Vec<SessionId>,
        request: ApprovalRequestId,
    },
    HistoryKeyReady {
        owner: UserId,
        to: Vec<SessionId>,
        device: DeviceId,
    },
}

#[derive(Default)]
pub struct RecordingDeviceTrustNotifier {
    sent: Mutex<Vec<SentTrust>>,
}

impl RecordingDeviceTrustNotifier {
    pub fn sent(&self) -> Vec<SentTrust> {
        self.sent.lock().unwrap().clone()
    }

    fn record(&self, sent: SentTrust) {
        self.sent.lock().unwrap().push(sent);
    }
}

impl DeviceTrustNotifier for RecordingDeviceTrustNotifier {
    fn device_approved(&self, owner: UserId, device: DeviceId) {
        self.record(SentTrust::Approved { owner, device });
    }

    fn approval_requested(
        &self,
        owner: UserId,
        to: &[SessionId],
        request: &ApprovalRequest,
        display_name: &str,
    ) {
        self.record(SentTrust::Requested {
            owner,
            to: to.to_vec(),
            request: request.id,
            device: request.device,
            display_name: display_name.to_owned(),
        });
    }

    fn approval_message(
        &self,
        owner: UserId,
        to: &[SessionId],
        request: ApprovalRequestId,
        seq: MessageSeq,
    ) {
        self.record(SentTrust::Message {
            owner,
            to: to.to_vec(),
            request,
            seq,
        });
    }

    fn approval_closed(&self, owner: UserId, to: &[SessionId], request: ApprovalRequestId) {
        self.record(SentTrust::Closed {
            owner,
            to: to.to_vec(),
            request,
        });
    }

    fn history_key_ready(&self, owner: UserId, to: &[SessionId], device: DeviceId) {
        self.record(SentTrust::HistoryKeyReady {
            owner,
            to: to.to_vec(),
            device,
        });
    }
}

/// What every store of approvals and approval requests must do.
pub mod contract {
    use time::Duration;

    use super::super::contract::{at, attestation, history_key, register};
    use super::*;
    use crate::e2ee::{ApprovalBy, ApprovalFacts, HistoryKey, approval_bytes, may_approve};

    pub(in crate::e2ee::testing) fn actor() -> ActorUri {
        ActorUri::parse("https://idp.test/users/alice_t3st0").unwrap()
    }

    /// A device of `owner`'s, its root key made of `key`s.
    async fn a_device(devices: &dyn Devices, owner: UserId, key: u8) -> DeviceId {
        let id = DeviceId::generate();
        register(devices, owner, id, &attestation(key), HpkeKeyWrite::Clear).await;
        id
    }

    pub(in crate::e2ee::testing) async fn found(devices: &dyn Devices, id: DeviceId) -> Device {
        devices.find(id).await.unwrap().expect("recorded")
    }

    pub(in crate::e2ee::testing) fn root_key(device: &Device) -> DeviceRootKey {
        device.attestation.as_ref().unwrap().root_key.clone()
    }

    /// `signer`'s approval of `approved`, signed and checked as a client and the use case would,
    /// on the devices as the store holds them now.
    pub(in crate::e2ee::testing) async fn by_device(
        devices: &dyn Devices,
        signer: DeviceId,
        approved: DeviceId,
    ) -> CheckedApproval {
        let (signer, approved_device) =
            (found(devices, signer).await, found(devices, approved).await);
        let signature = plain_signature(
            &root_key(&signer),
            &approval_bytes(&actor(), approved, &root_key(&approved_device)),
        );
        let facts = ApprovalFacts {
            actor: &actor(),
            signer: &signer,
            approved: Some(&approved_device),
            current: None,
        };
        may_approve(
            approved,
            ApprovalBy::Device,
            signature,
            facts,
            &PlainEd25519Verifier,
        )
        .expect("a well-made approval")
    }

    /// The passphrase's approval of `device`, with `key`'s approval key.
    pub(in crate::e2ee::testing) async fn by_passphrase(
        devices: &dyn Devices,
        device: DeviceId,
        key: &HistoryKey,
    ) -> CheckedApproval {
        let signer = found(devices, device).await;
        let signature = plain_signature(
            &key.approval_public_key,
            &approval_bytes(&actor(), device, &root_key(&signer)),
        );
        let facts = ApprovalFacts {
            actor: &actor(),
            signer: &signer,
            approved: Some(&signer),
            current: Some(key),
        };
        let by = ApprovalBy::Passphrase(key.generation);
        may_approve(device, by, signature, facts, &PlainEd25519Verifier)
            .expect("a well-made approval")
    }

    /// Each held approval as (approved device, approver).
    async fn held(approvals: &dyn DeviceApprovals, owner: UserId) -> Vec<(DeviceId, Approver)> {
        let mut held: Vec<_> = approvals
            .of_owner(owner)
            .await
            .unwrap()
            .into_iter()
            .map(|approval| (approval.device, approval.approver))
            .collect();
        held.sort_by_key(|(device, approver)| (*device, format!("{approver:?}")));
        held
    }

    fn sorted(mut pairs: Vec<(DeviceId, Approver)>) -> Vec<(DeviceId, Approver)> {
        pairs.sort_by_key(|(device, approver)| (*device, format!("{approver:?}")));
        pairs
    }

    /// `keys` is the store whose current generation `approvals` checks a passphrase against.
    pub async fn approvals_are_stored_once_per_approver_and_listed_by_owner(
        devices: &dyn Devices,
        approvals: &dyn DeviceApprovals,
        keys: &dyn HistoryKeys,
        alice: UserId,
        bob: UserId,
    ) {
        let (laptop, phone) = (
            a_device(devices, alice, 1).await,
            a_device(devices, alice, 2).await,
        );
        let (bobs, bobs_phone) = (
            a_device(devices, bob, 3).await,
            a_device(devices, bob, 4).await,
        );
        let first = history_key(1, 1);
        keys.replace(alice, &first, laptop).await.unwrap();
        let laptop_for_phone = by_device(devices, laptop, phone).await;

        let recorded = approvals.approve(alice, &laptop_for_phone).await.unwrap();
        let again = approvals.approve(alice, &laptop_for_phone).await.unwrap();
        let back = approvals
            .approve(alice, &by_device(devices, phone, laptop).await)
            .await
            .unwrap();
        let typed = by_passphrase(devices, phone, &first).await;
        let by_words = approvals.approve(alice, &typed).await.unwrap();
        let typed_again = approvals.approve(alice, &typed).await.unwrap();
        approvals
            .approve(bob, &by_device(devices, bobs, bobs_phone).await)
            .await
            .unwrap();

        assert_eq!(
            (recorded, again, back, by_words, typed_again),
            (
                Approve::Recorded,
                Approve::AlreadyHeld,
                Approve::Recorded,
                Approve::Recorded,
                Approve::AlreadyHeld
            )
        );
        assert_eq!(
            held(approvals, alice).await,
            sorted(vec![
                (phone, Approver::Device(laptop)),
                (laptop, Approver::Device(phone)),
                (phone, Approver::Passphrase(first.generation)),
            ])
        );
        let listed = approvals.of_owner(alice).await.unwrap();
        let of_phone = listed
            .iter()
            .find(|approval| approval.approver == Approver::Device(laptop))
            .unwrap();
        assert_eq!(
            (&of_phone.root_key, &of_phone.signature),
            (laptop_for_phone.root_key(), laptop_for_phone.signature())
        );
        assert_eq!(
            held(approvals, bob).await,
            vec![(bobs_phone, Approver::Device(bobs))]
        );
    }

    pub async fn an_approval_is_stored_only_while_what_it_was_checked_on_holds(
        devices: &dyn Devices,
        approvals: &dyn DeviceApprovals,
        keys: &dyn HistoryKeys,
        alice: UserId,
    ) {
        let laptop = a_device(devices, alice, 1).await;
        let (phone, tablet, watch, tv) = (
            a_device(devices, alice, 2).await,
            a_device(devices, alice, 3).await,
            a_device(devices, alice, 4).await,
            a_device(devices, alice, 5).await,
        );
        let first = history_key(1, 1);
        keys.replace(alice, &first, laptop).await.unwrap();
        let of_revoked = by_device(devices, laptop, phone).await;
        let by_revoked = by_device(devices, tablet, laptop).await;
        let of_rotated = by_device(devices, laptop, watch).await;
        let by_rotated = by_device(devices, tv, laptop).await;
        let under_the_first = by_passphrase(devices, laptop, &first).await;

        devices.revoke(alice, phone).await.unwrap();
        devices.revoke(alice, tablet).await.unwrap();
        register(devices, alice, watch, &attestation(9), HpkeKeyWrite::Clear).await;
        register(devices, alice, tv, &attestation(9), HpkeKeyWrite::Clear).await;
        keys.replace(alice, &history_key(2, 2), laptop)
            .await
            .unwrap();

        for stale in [
            of_revoked,
            by_revoked,
            of_rotated,
            by_rotated,
            under_the_first,
        ] {
            assert_eq!(
                approvals.approve(alice, &stale).await.unwrap(),
                Approve::Stale,
                "{stale:?}"
            );
        }
        assert_eq!(held(approvals, alice).await, vec![]);
    }

    pub async fn revoking_a_device_drops_the_approvals_it_signed(
        devices: &dyn Devices,
        approvals: &dyn DeviceApprovals,
        alice: UserId,
    ) {
        let (laptop, phone, tablet) = (
            a_device(devices, alice, 1).await,
            a_device(devices, alice, 2).await,
            a_device(devices, alice, 3).await,
        );
        for (signer, approved) in [
            (laptop, phone),
            (laptop, tablet),
            (phone, laptop),
            (phone, tablet),
        ] {
            let approval = by_device(devices, signer, approved).await;
            approvals.approve(alice, &approval).await.unwrap();
        }

        devices.revoke(alice, laptop).await.unwrap();

        assert_eq!(
            held(approvals, alice).await,
            sorted(vec![
                (laptop, Approver::Device(phone)),
                (tablet, Approver::Device(phone)),
            ])
        );
    }

    pub async fn a_new_root_key_drops_the_devices_approvals_and_those_it_signed(
        devices: &dyn Devices,
        approvals: &dyn DeviceApprovals,
        alice: UserId,
    ) {
        let (laptop, phone, tablet) = (
            a_device(devices, alice, 1).await,
            a_device(devices, alice, 2).await,
            a_device(devices, alice, 3).await,
        );
        for (signer, approved) in [
            (laptop, phone),
            (phone, laptop),
            (phone, tablet),
            (laptop, tablet),
        ] {
            let approval = by_device(devices, signer, approved).await;
            approvals.approve(alice, &approval).await.unwrap();
        }

        register(devices, alice, phone, &attestation(2), HpkeKeyWrite::Keep).await;
        let renewed = held(approvals, alice).await;
        register(devices, alice, phone, &attestation(8), HpkeKeyWrite::Clear).await;

        assert_eq!(renewed.len(), 4);
        assert_eq!(
            held(approvals, alice).await,
            vec![(tablet, Approver::Device(laptop))]
        );
    }

    pub async fn a_new_generation_drops_the_approvals_made_under_older_ones(
        devices: &dyn Devices,
        approvals: &dyn DeviceApprovals,
        keys: &dyn HistoryKeys,
        alice: UserId,
        bob: UserId,
    ) {
        let (laptop, phone) = (
            a_device(devices, alice, 1).await,
            a_device(devices, alice, 2).await,
        );
        let bobs = a_device(devices, bob, 3).await;
        let (first, second) = (history_key(1, 1), history_key(2, 2));
        keys.replace(alice, &first, laptop).await.unwrap();
        keys.replace(bob, &first, bobs).await.unwrap();
        for approval in [
            by_passphrase(devices, laptop, &first).await,
            by_passphrase(devices, phone, &first).await,
            by_device(devices, laptop, phone).await,
        ] {
            approvals.approve(alice, &approval).await.unwrap();
        }
        approvals
            .approve(bob, &by_passphrase(devices, bobs, &first).await)
            .await
            .unwrap();

        keys.replace(alice, &second, phone).await.unwrap();
        let after = held(approvals, alice).await;
        let anew = approvals
            .approve(alice, &by_passphrase(devices, laptop, &second).await)
            .await
            .unwrap();

        assert_eq!(after, vec![(phone, Approver::Device(laptop))]);
        assert_eq!(anew, Approve::Recorded);
        assert_eq!(
            held(approvals, bob).await,
            vec![(bobs, Approver::Passphrase(first.generation))]
        );
    }

    fn body(byte: u8) -> ApprovalMessageBody {
        ApprovalMessageBody::parse(vec![byte; 33]).unwrap()
    }

    /// A request of `device`'s opened at `opened_at`, and the requests it closed.
    async fn opened(
        requests: &dyn ApprovalRequests,
        devices: &dyn Devices,
        device: DeviceId,
        opened_at: OffsetDateTime,
    ) -> (ApprovalRequest, Vec<ApprovalRequest>) {
        let request = ApprovalRequest::open_for(&found(devices, device).await, opened_at).unwrap();
        match requests.open(&request).await.unwrap() {
            Opened::Opened { closed } => (request, closed),
            refused => panic!("{refused:?}"),
        }
    }

    async fn post(
        requests: &dyn ApprovalRequests,
        devices: &dyn Devices,
        request: &ApprovalRequest,
        from: DeviceId,
        byte: u8,
        now: OffsetDateTime,
    ) -> Post {
        let from = found(devices, from).await;
        requests
            .post(request.owner, request.id, &from, &body(byte), now)
            .await
            .unwrap()
    }

    /// What `reader` reads after `after`: each message's place, poster and body.
    async fn read(
        requests: &dyn ApprovalRequests,
        request: &ApprovalRequest,
        reader: DeviceId,
        after: MessageSeq,
        now: OffsetDateTime,
    ) -> Result<Vec<(MessageSeq, DeviceId, ApprovalMessageBody)>, RequestRefusal> {
        match requests
            .read(request.owner, request.id, reader, after, now)
            .await
            .unwrap()
        {
            Read::Messages(messages) => Ok(messages
                .into_iter()
                .map(|m| (m.seq, m.from, m.body))
                .collect()),
            Read::Refused(refusal) => Err(refusal),
        }
    }

    fn seq(raw: i64) -> MessageSeq {
        MessageSeq::parse(raw).unwrap()
    }

    fn ids(requests: &[ApprovalRequest]) -> Vec<ApprovalRequestId> {
        let mut ids: Vec<_> = requests.iter().map(|request| request.id).collect();
        ids.sort();
        ids
    }

    pub async fn opening_a_request_closes_the_devices_open_one(
        requests: &dyn ApprovalRequests,
        devices: &dyn Devices,
        alice: UserId,
    ) {
        let (laptop, phone) = (
            a_device(devices, alice, 1).await,
            a_device(devices, alice, 2).await,
        );
        let now = at(Duration::ZERO);
        let (expired, _) = opened(requests, devices, phone, now - Duration::minutes(20)).await;
        let (first, none_closed) =
            opened(requests, devices, laptop, now - Duration::minutes(2)).await;
        let (phones, expired_closed) =
            opened(requests, devices, phone, now - Duration::minutes(1)).await;

        let (second, closed) = opened(requests, devices, laptop, now).await;

        assert_eq!(none_closed, vec![]);
        assert_eq!(expired_closed, vec![], "{expired:?} was no longer open");
        assert_eq!(
            closed,
            vec![ApprovalRequest {
                closed_at: Some(now),
                ..first.clone()
            }]
        );
        assert_eq!(
            requests.open_of(alice, now).await.unwrap(),
            vec![phones, second]
        );
        assert_eq!(
            post(requests, devices, &first, phone, 1, now).await,
            Post::Refused(RequestRefusal::Ended)
        );
    }

    pub async fn an_account_opens_a_limited_number_of_requests_an_hour(
        requests: &dyn ApprovalRequests,
        devices: &dyn Devices,
        alice: UserId,
        bob: UserId,
    ) {
        let (laptop, phone) = (
            a_device(devices, alice, 1).await,
            a_device(devices, alice, 2).await,
        );
        let bobs = a_device(devices, bob, 3).await;
        let now = at(Duration::ZERO);
        for minute in 0..10 {
            opened(
                requests,
                devices,
                laptop,
                now - Duration::minutes(70 - minute),
            )
            .await;
        }
        for minute in 0..10 {
            let device = if minute % 2 == 0 { laptop } else { phone };
            opened(
                requests,
                devices,
                device,
                now - Duration::minutes(10 - minute),
            )
            .await;
        }
        let open_for = |device: Device| ApprovalRequest::open_for(&device, now).unwrap();

        let past_the_limit = requests
            .open(&open_for(found(devices, phone).await))
            .await
            .unwrap();
        let bobs_own = requests
            .open(&open_for(found(devices, bobs).await))
            .await
            .unwrap();

        assert_eq!(past_the_limit, Opened::TooMany);
        assert_eq!(bobs_own, Opened::Opened { closed: vec![] });
    }

    pub async fn the_first_message_from_another_device_binds_the_request(
        requests: &dyn ApprovalRequests,
        devices: &dyn Devices,
        alice: UserId,
    ) {
        let (laptop, phone, tablet) = (
            a_device(devices, alice, 1).await,
            a_device(devices, alice, 2).await,
            a_device(devices, alice, 3).await,
        );
        let now = at(Duration::ZERO);
        let (request, _) = opened(requests, devices, laptop, now).await;

        let asked = post(requests, devices, &request, laptop, 1, now).await;
        let read_by_anyone = read(requests, &request, tablet, MessageSeq::START, now).await;
        let answered = post(requests, devices, &request, phone, 2, now).await;
        let third = post(requests, devices, &request, tablet, 3, now).await;
        let read_by_a_third = read(requests, &request, tablet, MessageSeq::START, now).await;
        let again = post(requests, devices, &request, laptop, 4, now).await;

        let bound = ApprovalRequest {
            approver: Some(phone),
            ..request.clone()
        };
        assert_eq!(
            asked,
            Post::Posted {
                request: request.clone(),
                seq: seq(1),
                bound: false
            }
        );
        assert_eq!(
            answered,
            Post::Posted {
                request: bound.clone(),
                seq: seq(2),
                bound: true
            }
        );
        assert_eq!(third, Post::Refused(RequestRefusal::Taken));
        assert_eq!(
            again,
            Post::Posted {
                request: bound.clone(),
                seq: seq(3),
                bound: false
            }
        );
        assert_eq!(read_by_anyone, Ok(vec![(seq(1), laptop, body(1))]));
        assert_eq!(read_by_a_third, Err(RequestRefusal::Taken));
        assert_eq!(
            read(requests, &request, laptop, MessageSeq::START, now).await,
            Ok(vec![(seq(2), phone, body(2))])
        );
        assert_eq!(
            read(requests, &request, phone, seq(1), now).await,
            Ok(vec![(seq(3), laptop, body(4))])
        );
        assert_eq!(requests.open_of(alice, now).await.unwrap(), vec![bound]);
    }

    pub async fn a_request_takes_a_dozen_messages_while_open_and_ends_once(
        requests: &dyn ApprovalRequests,
        devices: &dyn Devices,
        alice: UserId,
        bob: UserId,
    ) {
        let (laptop, phone, tablet) = (
            a_device(devices, alice, 1).await,
            a_device(devices, alice, 2).await,
            a_device(devices, alice, 3).await,
        );
        let bobs = a_device(devices, bob, 4).await;
        let now = at(Duration::ZERO);
        let (full, _) = opened(requests, devices, laptop, now - Duration::seconds(3)).await;
        let (expiring, _) = opened(requests, devices, phone, now - Duration::seconds(2)).await;
        let (bound, _) = opened(requests, devices, tablet, now - Duration::seconds(1)).await;
        for i in 0..12 {
            let from = if i % 2 == 0 { laptop } else { phone };
            let posted = post(requests, devices, &full, from, i, now).await;
            assert!(matches!(posted, Post::Posted { .. }), "{posted:?}");
        }
        post(requests, devices, &bound, laptop, 1, now).await;
        let bobs_device = found(devices, bobs).await;

        let thirteenth = post(requests, devices, &full, laptop, 13, now).await;
        let too_late = post(requests, devices, &expiring, laptop, 1, expiring.expires_at).await;
        let unanswered_after = read(
            requests,
            &expiring,
            laptop,
            MessageSeq::START,
            expiring.expires_at,
        )
        .await;
        let anothers = requests
            .post(bob, full.id, &bobs_device, &body(1), now)
            .await
            .unwrap();
        let read_by_another = requests
            .read(bob, full.id, bobs, MessageSeq::START, now)
            .await
            .unwrap();
        let unknown = requests
            .close(alice, ApprovalRequestId::generate(), laptop, now)
            .await
            .unwrap();
        let closed_by_a_third = requests.close(alice, bound.id, phone, now).await.unwrap();
        let closed = requests.close(alice, bound.id, laptop, now).await.unwrap();
        let closed_again = requests.close(alice, bound.id, tablet, now).await.unwrap();
        let after_closing = post(requests, devices, &bound, tablet, 2, now).await;
        let asker_reads_after = read(requests, &bound, tablet, MessageSeq::START, now).await;
        let third_reads_after = read(requests, &bound, phone, MessageSeq::START, now).await;

        assert_eq!(thirteenth, Post::Refused(RequestRefusal::Full));
        assert_eq!(too_late, Post::Refused(RequestRefusal::Ended));
        assert_eq!(unanswered_after, Err(RequestRefusal::Ended));
        assert_eq!(anothers, Post::Refused(RequestRefusal::NotFound));
        assert_eq!(read_by_another, Read::Refused(RequestRefusal::NotFound));
        assert_eq!(unknown, Close::Refused(RequestRefusal::NotFound));
        assert_eq!(closed_by_a_third, Close::Refused(RequestRefusal::Taken));
        assert_eq!(
            closed,
            Close::Closed(ApprovalRequest {
                approver: Some(laptop),
                closed_at: Some(now),
                ..bound.clone()
            })
        );
        assert_eq!(closed_again, Close::Refused(RequestRefusal::Ended));
        assert_eq!(after_closing, Post::Refused(RequestRefusal::Ended));
        assert_eq!(asker_reads_after, Ok(vec![(seq(1), laptop, body(1))]));
        assert_eq!(third_reads_after, Err(RequestRefusal::Taken));
        let open: Vec<_> = requests
            .open_of(alice, now)
            .await
            .unwrap()
            .into_iter()
            .map(|request| request.id)
            .collect();
        assert_eq!(open, vec![full.id, expiring.id]);
    }

    /// `devices` closes the requests `requests` holds.
    pub async fn revoking_a_device_closes_the_requests_it_asks_or_answers(
        requests: &dyn ApprovalRequests,
        devices: &dyn Devices,
        alice: UserId,
    ) {
        let (laptop, phone, tablet) = (
            a_device(devices, alice, 1).await,
            a_device(devices, alice, 2).await,
            a_device(devices, alice, 3).await,
        );
        let now = at(Duration::ZERO);
        let (asked, _) = opened(requests, devices, laptop, now - Duration::seconds(2)).await;
        let (answered, _) = opened(requests, devices, tablet, now - Duration::seconds(1)).await;
        post(requests, devices, &answered, laptop, 1, now).await;
        let (unrelated, _) = opened(requests, devices, phone, now).await;

        let revoked = devices.revoke(alice, laptop).await.unwrap();

        let Revocation::Revoked { closed } = revoked else {
            panic!("{revoked:?}");
        };
        assert_eq!(ids(&closed), ids(&[asked.clone(), answered.clone()]));
        assert!(closed.iter().all(|request| request.closed_at.is_some()));
        assert_eq!(
            closed
                .iter()
                .find(|request| request.id == answered.id)
                .unwrap()
                .approver,
            Some(laptop)
        );
        assert_eq!(requests.open_of(alice, now).await.unwrap(), vec![unrelated]);
    }

    pub async fn requests_opened_before_the_cutoff_are_deleted_with_their_messages(
        requests: &dyn ApprovalRequests,
        devices: &dyn Devices,
        alice: UserId,
    ) {
        let (laptop, phone) = (
            a_device(devices, alice, 1).await,
            a_device(devices, alice, 2).await,
        );
        let now = at(Duration::ZERO);
        let (old, _) = opened(requests, devices, laptop, now - Duration::minutes(61)).await;
        let (recent, _) = opened(requests, devices, phone, now - Duration::minutes(59)).await;
        post(requests, devices, &old, laptop, 1, old.created_at).await;
        post(requests, devices, &recent, phone, 1, recent.created_at).await;

        let deleted = requests
            .delete_opened_before(now - Duration::hours(1))
            .await
            .unwrap();

        assert_eq!(deleted, 1);
        assert_eq!(
            read(requests, &old, laptop, MessageSeq::START, now).await,
            Err(RequestRefusal::NotFound)
        );
        assert_eq!(
            read(requests, &recent, phone, MessageSeq::START, now).await,
            Ok(vec![]),
            "the asking device's own message"
        );
        assert_eq!(
            read(
                requests,
                &recent,
                laptop,
                MessageSeq::START,
                recent.created_at
            )
            .await
            .map(|messages| messages.len()),
            Ok(1)
        );
    }
}
