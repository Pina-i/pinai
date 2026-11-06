//! The start over requests in memory, and the contract every store of them must satisfy.

use crate::StartOverRequestId;
use crate::e2ee::{
    StartOverEnded, StartOverOpened, StartOverOpening, StartOverRefusal, StartOverRequests,
    may_open_start_over, start_over_window,
};

use super::*;

#[async_trait::async_trait]
impl StartOverRequests for InMemoryKeyDirectory {
    async fn open(&self, request: &StartOverRequest) -> Result<StartOverOpened, KeyStoreError> {
        let unrevoked = self.state.lock().unwrap().devices.iter().any(|device| {
            device.id == request.device && device.owner == request.owner && !device.is_revoked()
        });
        if !unrevoked || self.generation(request.owner) != Some(request.generation) {
            return Ok(StartOverOpened::Stale);
        }
        let mut start_overs = self.start_overs.lock().unwrap();
        let of_owner = || start_overs.iter().filter(|r| r.owner == request.owner);
        let open = of_owner().find(|r| r.is_open());
        let opened = of_owner()
            .filter(|r| r.created_at > start_over_window(request.created_at))
            .count();
        match may_open_start_over(request, open, opened) {
            Ok(StartOverOpening::Existing(existing)) => Ok(StartOverOpened::Existing(existing)),
            Ok(StartOverOpening::Open) => {
                let request = StartOverRequest {
                    created_at: stored(request.created_at),
                    ..request.clone()
                };
                start_overs.push(request.clone());
                Ok(StartOverOpened::Opened(request))
            }
            Err(refusal) => Ok(StartOverOpened::Refused(refusal)),
        }
    }

    async fn open_of(&self, owner: UserId) -> Result<Option<StartOverRequest>, KeyStoreError> {
        Ok(self
            .start_overs
            .lock()
            .unwrap()
            .iter()
            .find(|r| r.owner == owner && r.is_open())
            .cloned())
    }

    async fn latest_of(
        &self,
        owner: UserId,
        device: DeviceId,
    ) -> Result<Option<StartOverRequest>, KeyStoreError> {
        Ok(self
            .start_overs
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.owner == owner && r.device == device)
            .max_by_key(|r| r.created_at)
            .cloned())
    }

    async fn request(
        &self,
        owner: UserId,
        id: StartOverRequestId,
    ) -> Result<Option<StartOverRequest>, KeyStoreError> {
        Ok(self
            .start_overs
            .lock()
            .unwrap()
            .iter()
            .find(|r| r.owner == owner && r.id == id)
            .cloned())
    }

    async fn end(
        &self,
        owner: UserId,
        id: StartOverRequestId,
        by: DeviceId,
        how: StartOverEnd,
        now: OffsetDateTime,
    ) -> Result<StartOverEnded, KeyStoreError> {
        let unrevoked = self
            .state
            .lock()
            .unwrap()
            .devices
            .iter()
            .any(|device| device.id == by && device.owner == owner && !device.is_revoked());
        if !unrevoked {
            return Ok(StartOverEnded::Stale);
        }
        let trust = self.trust_of(owner);
        let mut start_overs = self.start_overs.lock().unwrap();
        let Some(request) = start_overs
            .iter_mut()
            .find(|r| r.owner == owner && r.id == id)
        else {
            return Ok(StartOverEnded::Refused(StartOverRefusal::NotFound));
        };
        if !request.is_open() {
            return Ok(StartOverEnded::Refused(StartOverRefusal::Ended));
        }
        if request.may_end(by, &trust).ok() != Some(how) {
            return Ok(StartOverEnded::Stale);
        }
        request.ended = Some(StartOverEnding {
            how,
            at: stored(now),
        });
        Ok(StartOverEnded::Ended(request.clone()))
    }

    async fn delete_ended_before(&self, cutoff: OffsetDateTime) -> Result<usize, KeyStoreError> {
        let mut start_overs = self.start_overs.lock().unwrap();
        let before = start_overs.len();
        start_overs.retain(|r| r.ended.is_none_or(|ended| ended.at >= cutoff));
        Ok(before - start_overs.len())
    }
}

/// What every store of start over requests must do, with the history keys, devices and sessions
/// they share a database with.
pub mod contract {
    use time::Duration;

    use super::super::approval::contract::{by_device, by_passphrase, found};
    use super::super::contract::{at, attestation, history_key, register};
    use super::*;
    use crate::SessionId;
    use crate::auth::Sessions;
    use crate::auth::testing::a_request;
    use crate::e2ee::{
        ApprovalRequired, Approve, DeviceApprovals, HistoryKey, START_OVER_KEPT, START_OVER_WAIT,
        start_over_sweep_before,
    };

    /// The stores a start over is decided on and kept in, over one database.
    #[derive(Clone, Copy)]
    pub struct StartOverStores<'a> {
        pub devices: &'a dyn Devices,
        pub approvals: &'a dyn DeviceApprovals,
        pub keys: &'a dyn HistoryKeys,
        pub start_overs: &'a dyn StartOverRequests,
        pub sessions: &'a dyn Sessions,
    }

    /// A device of `owner`'s, its root key made of `key`s.
    pub async fn a_new_device(s: StartOverStores<'_>, owner: UserId, key: u8) -> DeviceId {
        let id = DeviceId::generate();
        register(s.devices, owner, id, &attestation(key), HpkeKeyWrite::Clear).await;
        id
    }

    /// `device` approved by `key`'s words.
    pub async fn approved_by_words(
        s: StartOverStores<'_>,
        owner: UserId,
        device: DeviceId,
        key: &HistoryKey,
    ) {
        let approval = by_passphrase(s.devices, device, key).await;
        s.approvals
            .approve(owner, &approval)
            .await
            .expect("the words of the current generation");
    }

    /// `owner`'s laptop, which set `first` and is approved by it.
    pub async fn an_account(s: StartOverStores<'_>, owner: UserId, first: &HistoryKey) -> DeviceId {
        let laptop = a_new_device(s, owner, 1).await;
        s.keys
            .replace(owner, first, laptop, at(Duration::ZERO))
            .await
            .unwrap();
        approved_by_words(s, owner, laptop, first).await;
        laptop
    }

    /// `approver`'s approval of `device`, signed and stored.
    pub async fn approved_by(
        s: StartOverStores<'_>,
        owner: UserId,
        approver: DeviceId,
        device: DeviceId,
    ) -> Approve {
        let approval = by_device(s.devices, approver, device).await;
        s.approvals.approve(owner, &approval).await.unwrap()
    }

    /// A session of `device`'s, signed in and last used `at`.
    pub async fn signed_in(
        s: StartOverStores<'_>,
        owner: UserId,
        device: DeviceId,
        at: OffsetDateTime,
    ) -> SessionId {
        let browser = s.sessions.open_browser(owner, at).await.unwrap();
        let session = s
            .sessions
            .open_under(browser, &a_request().client, at)
            .await
            .unwrap()
            .expect("a live browser session")
            .id;
        s.sessions.link(owner, session, device, at).await.unwrap();
        session
    }

    /// `device`'s request, opened `now` on what the stores hold.
    pub async fn request_of(
        s: StartOverStores<'_>,
        owner: UserId,
        device: DeviceId,
        now: OffsetDateTime,
    ) -> StartOverRequest {
        let trust = s.approvals.trust(owner).await.unwrap();
        StartOverRequest::open_for(&found(s.devices, device).await, &trust, now)
            .expect("a device not approved")
    }

    async fn open(
        s: StartOverStores<'_>,
        owner: UserId,
        device: DeviceId,
        now: OffsetDateTime,
    ) -> (StartOverRequest, StartOverOpened) {
        let request = request_of(s, owner, device, now).await;
        let opened = s.start_overs.open(&request).await.unwrap();
        (request, opened)
    }

    /// What the races start from: `owner`'s laptop approved under generation 1, a fresh device's
    /// request opened a week before `ready`, matured then with no session in use, and the
    /// generation it allows.
    pub struct Matured {
        pub laptop: DeviceId,
        pub fresh: DeviceId,
        pub request: StartOverRequest,
        pub ready: OffsetDateTime,
        pub next: HistoryKey,
    }

    pub async fn a_matured_start_over(s: StartOverStores<'_>, owner: UserId) -> Matured {
        let laptop = an_account(s, owner, &history_key(1, 1)).await;
        let fresh = a_new_device(s, owner, 2).await;
        let ready = at(Duration::ZERO);
        let (request, opened) = open(s, owner, fresh, ready - START_OVER_WAIT).await;
        assert_eq!(opened, StartOverOpened::Opened(request.clone()));
        Matured {
            laptop,
            fresh,
            request,
            ready,
            next: history_key(2, 2),
        }
    }

    fn how(request: Option<StartOverRequest>) -> Option<StartOverEnd> {
        request
            .and_then(|request| request.ended)
            .map(|ended| ended.how)
    }

    pub async fn a_device_has_one_request_open_and_asking_again_answers_it(
        s: StartOverStores<'_>,
        alice: UserId,
    ) {
        an_account(s, alice, &history_key(1, 1)).await;
        let (fresh, other) = (
            a_new_device(s, alice, 2).await,
            a_new_device(s, alice, 3).await,
        );
        let now = at(Duration::ZERO);

        let (first, opened) = open(s, alice, fresh, now).await;
        let (_, again) = open(s, alice, fresh, now + Duration::seconds(5)).await;
        let (_, anothers) = open(s, alice, other, now).await;

        assert_eq!(opened, StartOverOpened::Opened(first.clone()));
        assert_eq!(again, StartOverOpened::Existing(first.clone()));
        assert_eq!(
            anothers,
            StartOverOpened::Refused(StartOverRefusal::Pending)
        );
        assert_eq!(
            s.start_overs.open_of(alice).await.unwrap(),
            Some(first.clone())
        );
        assert_eq!(
            s.start_overs.request(alice, first.id).await.unwrap(),
            Some(first.clone())
        );
        assert_eq!(
            s.start_overs.latest_of(alice, fresh).await.unwrap(),
            Some(first)
        );
        assert_eq!(s.start_overs.latest_of(alice, other).await.unwrap(), None);
    }

    pub async fn a_request_is_held_to_the_microsecond_as_the_store_answers_it(
        s: StartOverStores<'_>,
        alice: UserId,
    ) {
        an_account(s, alice, &history_key(1, 1)).await;
        let fresh = a_new_device(s, alice, 2).await;
        let now = at(Duration::ZERO) + Duration::nanoseconds(123_456_789);

        let (asked, opened) = open(s, alice, fresh, now).await;

        let held = StartOverRequest {
            created_at: at(Duration::ZERO) + Duration::microseconds(123_456),
            ..asked
        };
        assert_eq!(opened, StartOverOpened::Opened(held.clone()));
        assert_eq!(s.start_overs.open_of(alice).await.unwrap(), Some(held));
    }

    pub async fn an_account_opens_three_requests_a_day(s: StartOverStores<'_>, alice: UserId) {
        let laptop = an_account(s, alice, &history_key(1, 1)).await;
        let fresh = a_new_device(s, alice, 2).await;
        let now = at(Duration::ZERO);
        let yesterday = now - Duration::days(1) - Duration::seconds(1);

        let (old, _) = open(s, alice, fresh, yesterday).await;
        s.start_overs
            .end(alice, old.id, laptop, StartOverEnd::Cancelled, yesterday)
            .await
            .unwrap();
        let mut answers = Vec::new();
        for minute in 0..4 {
            let (request, opened) = open(s, alice, fresh, now + Duration::minutes(minute)).await;
            if opened == StartOverOpened::Opened(request.clone()) {
                s.start_overs
                    .end(alice, request.id, fresh, StartOverEnd::Withdrawn, now)
                    .await
                    .unwrap();
            }
            answers.push(opened);
        }

        assert!(
            answers[..3]
                .iter()
                .all(|answer| matches!(answer, StartOverOpened::Opened(_))),
            "{answers:?}"
        );
        assert_eq!(
            answers[3],
            StartOverOpened::Refused(StartOverRefusal::TooMany)
        );
    }

    pub async fn a_request_is_opened_only_while_its_device_and_generation_hold(
        s: StartOverStores<'_>,
        alice: UserId,
    ) {
        let first = history_key(1, 1);
        let laptop = an_account(s, alice, &first).await;
        let (revoked, late) = (
            a_new_device(s, alice, 2).await,
            a_new_device(s, alice, 3).await,
        );
        let now = at(Duration::ZERO);
        let of_the_revoked = request_of(s, alice, revoked, now).await;
        let under_generation_one = request_of(s, alice, late, now).await;

        s.devices
            .revoke(alice, revoked, Some(laptop), now)
            .await
            .unwrap();
        let revoked_meanwhile = s.start_overs.open(&of_the_revoked).await.unwrap();
        s.keys
            .replace(alice, &history_key(2, 2), laptop, now)
            .await
            .unwrap();
        let moved_on = s.start_overs.open(&under_generation_one).await.unwrap();

        assert_eq!(revoked_meanwhile, StartOverOpened::Stale);
        assert_eq!(moved_on, StartOverOpened::Stale);
        assert_eq!(s.start_overs.open_of(alice).await.unwrap(), None);
    }

    pub async fn a_request_ends_once_and_only_for_its_account(
        s: StartOverStores<'_>,
        alice: UserId,
        bob: UserId,
    ) {
        let laptop = an_account(s, alice, &history_key(1, 1)).await;
        let fresh = a_new_device(s, alice, 2).await;
        let bobs = a_new_device(s, bob, 3).await;
        let now = at(Duration::ZERO);
        let (request, _) = open(s, alice, fresh, now).await;

        let by_bob = s
            .start_overs
            .end(bob, request.id, bobs, StartOverEnd::Cancelled, now)
            .await
            .unwrap();
        let cancelled = s
            .start_overs
            .end(alice, request.id, laptop, StartOverEnd::Cancelled, now)
            .await
            .unwrap();
        let again = s
            .start_overs
            .end(alice, request.id, fresh, StartOverEnd::Withdrawn, now)
            .await
            .unwrap();
        let unknown = s
            .start_overs
            .end(
                alice,
                StartOverRequestId::generate(),
                laptop,
                StartOverEnd::Cancelled,
                now,
            )
            .await
            .unwrap();

        let ended = StartOverRequest {
            ended: Some(StartOverEnding {
                how: StartOverEnd::Cancelled,
                at: now,
            }),
            ..request.clone()
        };
        assert_eq!(by_bob, StartOverEnded::Refused(StartOverRefusal::NotFound));
        assert_eq!(cancelled, StartOverEnded::Ended(ended.clone()));
        assert_eq!(again, StartOverEnded::Refused(StartOverRefusal::Ended));
        assert_eq!(unknown, StartOverEnded::Refused(StartOverRefusal::NotFound));
        assert_eq!(s.start_overs.open_of(alice).await.unwrap(), None);
        assert_eq!(
            s.start_overs.request(alice, request.id).await.unwrap(),
            Some(ended.clone())
        );
        assert_eq!(
            s.start_overs.latest_of(alice, fresh).await.unwrap(),
            Some(ended)
        );
        assert_eq!(s.start_overs.request(bob, request.id).await.unwrap(), None);
    }

    pub async fn a_request_is_ended_only_as_its_ender_still_may(
        s: StartOverStores<'_>,
        alice: UserId,
    ) {
        let laptop = an_account(s, alice, &history_key(1, 1)).await;
        let (fresh, tablet, other) = (
            a_new_device(s, alice, 2).await,
            a_new_device(s, alice, 3).await,
            a_new_device(s, alice, 4).await,
        );
        let now = at(Duration::ZERO);
        let (request, _) = open(s, alice, fresh, now).await;
        s.devices
            .revoke(alice, tablet, Some(laptop), now)
            .await
            .unwrap();

        let by_the_revoked = s
            .start_overs
            .end(alice, request.id, tablet, StartOverEnd::Cancelled, now)
            .await
            .unwrap();
        let by_one_not_approved = s
            .start_overs
            .end(alice, request.id, other, StartOverEnd::Cancelled, now)
            .await
            .unwrap();
        let withdrawn_by_another = s
            .start_overs
            .end(alice, request.id, laptop, StartOverEnd::Withdrawn, now)
            .await
            .unwrap();

        for stale in [by_the_revoked, by_one_not_approved, withdrawn_by_another] {
            assert_eq!(stale, StartOverEnded::Stale);
        }
        assert!(s.start_overs.open_of(alice).await.unwrap().is_some());
    }

    pub async fn revoking_the_asking_device_cancels_its_request(
        s: StartOverStores<'_>,
        alice: UserId,
    ) {
        let laptop = an_account(s, alice, &history_key(1, 1)).await;
        let fresh = a_new_device(s, alice, 2).await;
        let now = at(Duration::ZERO);
        let (request, _) = open(s, alice, fresh, now).await;

        let revoked = s
            .devices
            .revoke(alice, fresh, Some(laptop), now)
            .await
            .unwrap();

        let Revocation::Revoked {
            start_over: Some(cancelled),
            ..
        } = revoked
        else {
            panic!("{revoked:?}");
        };
        assert_eq!(cancelled.id, request.id);
        assert_eq!(
            cancelled.ended,
            Some(StartOverEnding {
                how: StartOverEnd::Revoked,
                at: now
            })
        );
        assert_eq!(s.start_overs.open_of(alice).await.unwrap(), None);
    }

    pub async fn an_approval_that_makes_the_asking_device_approved_ends_its_request(
        s: StartOverStores<'_>,
        alice: UserId,
    ) {
        let laptop = an_account(s, alice, &history_key(1, 1)).await;
        let (fresh, other) = (
            a_new_device(s, alice, 2).await,
            a_new_device(s, alice, 3).await,
        );
        let (request, _) = open(s, alice, fresh, at(Duration::ZERO)).await;

        let by_one_not_approved = approved_by(s, alice, other, fresh).await;
        let still_open = s.start_overs.open_of(alice).await.unwrap();
        let by_the_laptop = approved_by(s, alice, laptop, fresh).await;

        assert_eq!(by_one_not_approved, Approve::Recorded { start_over: None });
        assert_eq!(still_open.map(|open| open.id), Some(request.id));
        let Approve::Recorded {
            start_over: Some(ended),
        } = by_the_laptop
        else {
            panic!("{by_the_laptop:?}");
        };
        assert_eq!(ended.id, request.id);
        assert_eq!(how(Some(ended)), Some(StartOverEnd::Approved));
        assert_eq!(s.start_overs.open_of(alice).await.unwrap(), None);
    }

    pub async fn a_matured_request_sets_the_next_generation_and_is_used_by_it(
        s: StartOverStores<'_>,
        alice: UserId,
    ) {
        let m = a_matured_start_over(s, alice).await;

        let too_soon = s
            .keys
            .replace(alice, &m.next, m.fresh, m.ready - Duration::seconds(1))
            .await
            .unwrap();
        let replaced = s
            .keys
            .replace(alice, &m.next, m.fresh, m.ready)
            .await
            .unwrap();

        assert_eq!(
            too_soon,
            KeyReplace::Refused(StartOverRefusal::NotReady { ready_at: m.ready })
        );
        assert_eq!(
            replaced,
            KeyReplace::Replaced {
                erased: 0,
                closed: vec![]
            }
        );
        let held = s.keys.current(alice).await.unwrap().unwrap();
        assert_eq!((held.key, held.set_by), (m.next, Some(m.fresh)));
        let used = s.start_overs.request(alice, m.request.id).await.unwrap();
        assert_eq!(
            used.unwrap().ended,
            Some(StartOverEnding {
                how: StartOverEnd::Used,
                at: m.ready
            })
        );
        assert_eq!(s.start_overs.open_of(alice).await.unwrap(), None);
    }

    pub async fn a_start_over_after_an_approved_device_was_used_writes_nothing(
        s: StartOverStores<'_>,
        alice: UserId,
    ) {
        let m = a_matured_start_over(s, alice).await;
        let laptops = signed_in(s, alice, m.laptop, m.ready - Duration::days(8)).await;
        let used = m.ready - Duration::minutes(1);
        s.sessions.touch(laptops, used).await.unwrap();

        let refused = s
            .keys
            .replace(alice, &m.next, m.fresh, m.ready)
            .await
            .unwrap();

        assert_eq!(
            refused,
            KeyReplace::Refused(StartOverRefusal::NotReady {
                ready_at: used + START_OVER_WAIT
            })
        );
        let held = s.keys.current(alice).await.unwrap().unwrap();
        assert_eq!(held.key.generation, HistoryGeneration::FIRST);
        assert_eq!(s.start_overs.open_of(alice).await.unwrap(), Some(m.request));
    }

    pub async fn a_start_over_whose_request_ended_writes_nothing(
        s: StartOverStores<'_>,
        alice: UserId,
    ) {
        let m = a_matured_start_over(s, alice).await;
        s.start_overs
            .end(
                alice,
                m.request.id,
                m.laptop,
                StartOverEnd::Cancelled,
                m.ready,
            )
            .await
            .unwrap();

        let replaced = s
            .keys
            .replace(alice, &m.next, m.fresh, m.ready)
            .await
            .unwrap();

        assert_eq!(replaced, KeyReplace::Refused(StartOverRefusal::Required));
        let held = s.keys.current(alice).await.unwrap().unwrap();
        assert_eq!(held.key, history_key(1, 1));
    }

    pub async fn a_setter_no_longer_approved_writes_nothing(s: StartOverStores<'_>, alice: UserId) {
        let first = history_key(1, 1);
        let laptop = an_account(s, alice, &first).await;
        let phone = a_new_device(s, alice, 2).await;
        approved_by(s, alice, laptop, phone).await;
        let now = at(Duration::ZERO);
        s.devices
            .revoke(alice, laptop, Some(laptop), now)
            .await
            .unwrap();

        let by_the_phone = s
            .keys
            .replace(alice, &history_key(2, 2), phone, now)
            .await
            .unwrap();

        assert_eq!(
            by_the_phone,
            KeyReplace::Refused(StartOverRefusal::Required)
        );
        assert_eq!(s.keys.current(alice).await.unwrap().unwrap().key, first);
    }

    pub async fn a_new_generation_from_an_approved_device_supersedes_the_open_request(
        s: StartOverStores<'_>,
        alice: UserId,
    ) {
        let laptop = an_account(s, alice, &history_key(1, 1)).await;
        let fresh = a_new_device(s, alice, 2).await;
        let now = at(Duration::ZERO);
        let (request, _) = open(s, alice, fresh, now).await;

        let replaced = s
            .keys
            .replace(alice, &history_key(2, 2), laptop, now)
            .await
            .unwrap();

        let KeyReplace::Replaced { closed, .. } = replaced else {
            panic!("{replaced:?}");
        };
        assert_eq!(closed.len(), 1);
        assert_eq!(closed[0].id, request.id);
        assert_eq!(
            closed[0].ended,
            Some(StartOverEnding {
                how: StartOverEnd::Superseded,
                at: now
            })
        );
        assert_eq!(s.start_overs.open_of(alice).await.unwrap(), None);
    }

    pub async fn requests_that_ended_are_swept_a_week_after_they_ended(
        s: StartOverStores<'_>,
        alice: UserId,
    ) {
        let laptop = an_account(s, alice, &history_key(1, 1)).await;
        let fresh = a_new_device(s, alice, 2).await;
        let now = at(Duration::ZERO);
        let long_ago = now - START_OVER_KEPT - Duration::days(1);
        let (old, _) = open(s, alice, fresh, long_ago).await;
        s.start_overs
            .end(alice, old.id, laptop, StartOverEnd::Cancelled, long_ago)
            .await
            .unwrap();
        let (recent, _) = open(s, alice, fresh, long_ago + Duration::hours(1)).await;
        s.start_overs
            .end(alice, recent.id, fresh, StartOverEnd::Withdrawn, now)
            .await
            .unwrap();
        let (open_since, _) = open(s, alice, fresh, long_ago).await;

        let swept = s
            .start_overs
            .delete_ended_before(start_over_sweep_before(now))
            .await
            .unwrap();

        assert_eq!(swept, 1);
        assert_eq!(s.start_overs.request(alice, old.id).await.unwrap(), None);
        assert!(
            s.start_overs
                .request(alice, recent.id)
                .await
                .unwrap()
                .is_some(),
            "ended a week ago at most"
        );
        assert_eq!(
            s.start_overs.open_of(alice).await.unwrap(),
            Some(open_since)
        );
    }

    pub async fn an_approved_device_is_revoked_only_from_an_approved_device(
        s: StartOverStores<'_>,
        alice: UserId,
    ) {
        let laptop = an_account(s, alice, &history_key(1, 1)).await;
        let phone = a_new_device(s, alice, 2).await;
        approved_by(s, alice, laptop, phone).await;
        let (fresh, other) = (
            a_new_device(s, alice, 3).await,
            a_new_device(s, alice, 4).await,
        );
        let now = at(Duration::ZERO);

        let refused = s
            .devices
            .revoke(alice, phone, Some(fresh), now)
            .await
            .unwrap();
        let still_there = !found(s.devices, phone).await.is_revoked();
        let unnamed = s.devices.revoke(alice, laptop, None, now).await.unwrap();
        let unapproved = s
            .devices
            .revoke(alice, other, Some(fresh), now)
            .await
            .unwrap();
        let itself = s
            .devices
            .revoke(alice, fresh, Some(fresh), now)
            .await
            .unwrap();
        let approved = s
            .devices
            .revoke(alice, phone, Some(laptop), now)
            .await
            .unwrap();

        assert_eq!(refused, Revocation::Refused(ApprovalRequired));
        assert_eq!(unnamed, Revocation::Refused(ApprovalRequired));
        assert!(still_there, "nothing written");
        for revoked in [unapproved, itself, approved] {
            assert!(matches!(revoked, Revocation::Revoked { .. }), "{revoked:?}");
        }
        assert_eq!(found(s.devices, phone).await.revoked_at, Some(now));
    }

    pub async fn an_account_with_no_history_key_revokes_any_device_of_its_own(
        s: StartOverStores<'_>,
        alice: UserId,
    ) {
        let (laptop, phone) = (
            a_new_device(s, alice, 1).await,
            a_new_device(s, alice, 2).await,
        );

        let revoked = s
            .devices
            .revoke(alice, laptop, Some(phone), at(Duration::ZERO))
            .await
            .unwrap();

        assert!(matches!(revoked, Revocation::Revoked { .. }), "{revoked:?}");
    }

    pub async fn the_trust_read_holds_the_accounts_devices_approvals_and_generation(
        s: StartOverStores<'_>,
        alice: UserId,
        bob: UserId,
    ) {
        let first = history_key(1, 1);
        let laptop = an_account(s, alice, &first).await;
        let phone = a_new_device(s, alice, 2).await;
        a_new_device(s, bob, 3).await;

        let trust = s.approvals.trust(alice).await.unwrap();

        let mut devices: Vec<DeviceId> = trust.devices.iter().map(|d| d.id).collect();
        devices.sort();
        let mut expected = vec![laptop, phone];
        expected.sort();
        assert_eq!(devices, expected);
        assert_eq!(trust.approvals, s.approvals.of_owner(alice).await.unwrap());
        assert_eq!(trust.current, Some(first.generation));
        assert!(trust.is_approved(laptop) && !trust.is_approved(phone));
        assert_eq!(s.approvals.trust(bob).await.unwrap().current, None);
    }
}
