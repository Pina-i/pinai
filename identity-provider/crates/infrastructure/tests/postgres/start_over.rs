use std::sync::Arc;

use domain::auth::Sessions;
use domain::e2ee::testing::contract::{self, Matured, StartOverStores};
use domain::e2ee::{
    ApprovalRequired, Devices, HistoryGeneration, HistoryKey, HistoryKeys, KeyReplace, Revocation,
    StartOverEnd, StartOverEnded, StartOverOpened, StartOverRefusal, StartOverRequests,
};
use domain::{DeviceId, UserId};
use infrastructure::postgres::{
    PgDeviceApprovals, PgDevices, PgHistoryKeys, PgSessions, PgStartOverRequests,
};
use sqlx::PgPool;
use time::OffsetDateTime;

use super::a_user;

/// The stores of one database.
pub(crate) struct Stores {
    pub(crate) devices: PgDevices,
    pub(crate) approvals: PgDeviceApprovals,
    pub(crate) keys: PgHistoryKeys,
    pub(crate) start_overs: PgStartOverRequests,
    pub(crate) sessions: PgSessions,
}

impl Stores {
    pub(crate) fn of(pool: &PgPool) -> Self {
        Self {
            devices: PgDevices::new(pool.clone()),
            approvals: PgDeviceApprovals::new(pool.clone()),
            keys: PgHistoryKeys::new(pool.clone()),
            start_overs: PgStartOverRequests::new(pool.clone()),
            sessions: PgSessions::new(pool.clone()),
        }
    }

    pub(crate) fn view(&self) -> StartOverStores<'_> {
        StartOverStores {
            devices: &self.devices,
            approvals: &self.approvals,
            keys: &self.keys,
            start_overs: &self.start_overs,
            sessions: &self.sessions,
        }
    }
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_device_has_one_request_open_and_asking_again_answers_it(pool: PgPool) {
    let alice = a_user(&pool).await;
    contract::a_device_has_one_request_open_and_asking_again_answers_it(
        Stores::of(&pool).view(),
        alice,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_request_is_held_to_the_microsecond_as_the_store_answers_it(pool: PgPool) {
    let alice = a_user(&pool).await;
    contract::a_request_is_held_to_the_microsecond_as_the_store_answers_it(
        Stores::of(&pool).view(),
        alice,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn an_account_opens_three_requests_a_day(pool: PgPool) {
    let alice = a_user(&pool).await;
    contract::an_account_opens_three_requests_a_day(Stores::of(&pool).view(), alice).await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_request_is_opened_only_while_its_device_and_generation_hold(pool: PgPool) {
    let alice = a_user(&pool).await;
    contract::a_request_is_opened_only_while_its_device_and_generation_hold(
        Stores::of(&pool).view(),
        alice,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_request_ends_once_and_only_for_its_account(pool: PgPool) {
    let (alice, bob) = (a_user(&pool).await, a_user(&pool).await);
    contract::a_request_ends_once_and_only_for_its_account(Stores::of(&pool).view(), alice, bob)
        .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_request_is_ended_only_as_its_ender_still_may(pool: PgPool) {
    let alice = a_user(&pool).await;
    contract::a_request_is_ended_only_as_its_ender_still_may(Stores::of(&pool).view(), alice).await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn revoking_the_asking_device_cancels_its_request(pool: PgPool) {
    let alice = a_user(&pool).await;
    contract::revoking_the_asking_device_cancels_its_request(Stores::of(&pool).view(), alice).await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn an_approval_that_makes_the_asking_device_approved_ends_its_request(pool: PgPool) {
    let alice = a_user(&pool).await;
    contract::an_approval_that_makes_the_asking_device_approved_ends_its_request(
        Stores::of(&pool).view(),
        alice,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_matured_request_sets_the_next_generation_and_is_used_by_it(pool: PgPool) {
    let alice = a_user(&pool).await;
    contract::a_matured_request_sets_the_next_generation_and_is_used_by_it(
        Stores::of(&pool).view(),
        alice,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_start_over_after_an_approved_device_was_used_writes_nothing(pool: PgPool) {
    let alice = a_user(&pool).await;
    contract::a_start_over_after_an_approved_device_was_used_writes_nothing(
        Stores::of(&pool).view(),
        alice,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_start_over_whose_request_ended_writes_nothing(pool: PgPool) {
    let alice = a_user(&pool).await;
    contract::a_start_over_whose_request_ended_writes_nothing(Stores::of(&pool).view(), alice)
        .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_setter_no_longer_approved_writes_nothing(pool: PgPool) {
    let alice = a_user(&pool).await;
    contract::a_setter_no_longer_approved_writes_nothing(Stores::of(&pool).view(), alice).await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_new_generation_from_an_approved_device_supersedes_the_open_request(pool: PgPool) {
    let alice = a_user(&pool).await;
    contract::a_new_generation_from_an_approved_device_supersedes_the_open_request(
        Stores::of(&pool).view(),
        alice,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn requests_that_ended_are_swept_a_week_after_they_ended(pool: PgPool) {
    let alice = a_user(&pool).await;
    contract::requests_that_ended_are_swept_a_week_after_they_ended(
        Stores::of(&pool).view(),
        alice,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn an_approved_device_is_revoked_only_from_an_approved_device(pool: PgPool) {
    let alice = a_user(&pool).await;
    contract::an_approved_device_is_revoked_only_from_an_approved_device(
        Stores::of(&pool).view(),
        alice,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn an_account_with_no_history_key_revokes_any_device_of_its_own(pool: PgPool) {
    let alice = a_user(&pool).await;
    contract::an_account_with_no_history_key_revokes_any_device_of_its_own(
        Stores::of(&pool).view(),
        alice,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn the_trust_read_holds_the_accounts_devices_approvals_and_generation(pool: PgPool) {
    let (alice, bob) = (a_user(&pool).await, a_user(&pool).await);
    contract::the_trust_read_holds_the_accounts_devices_approvals_and_generation(
        Stores::of(&pool).view(),
        alice,
        bob,
    )
    .await;
}

async fn a_matured_start_over(pool: &PgPool, stores: &Stores) -> (UserId, Matured) {
    let alice = a_user(pool).await;
    (
        alice,
        contract::a_matured_start_over(stores.view(), alice).await,
    )
}

fn first_key() -> HistoryKey {
    HistoryKey {
        generation: HistoryGeneration::FIRST,
        salt: domain::e2ee::HistorySalt::parse(&[1; 16]).unwrap(),
        check_value: domain::e2ee::HistoryCheckValue::parse(&[1; 32]).unwrap(),
        approval_public_key: domain::e2ee::ApprovalPublicKey::parse(&[1; 32]).unwrap(),
    }
}

/// A web app's session of `user`'s, used `at`, naming no device yet.
async fn a_web_app_of(
    sessions: &PgSessions,
    user: UserId,
    at: OffsetDateTime,
) -> domain::SessionId {
    let browser = sessions.open_browser(user, at).await.unwrap();
    sessions
        .open_under(browser, &domain::auth::testing::a_request().client, at)
        .await
        .unwrap()
        .unwrap()
        .id
}

/// A request maturing as an approved device signs in: the sign-in comes first and the write is
/// refused, or the write does and the sign-in follows it.
#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_request_maturing_as_an_approved_device_signs_in_goes_one_way_or_the_other(pool: PgPool) {
    let stores = Arc::new(Stores::of(&pool));

    for _ in 0..10 {
        let (alice, m) = a_matured_start_over(&pool, &stores).await;
        let session = a_web_app_of(&stores.sessions, alice, m.ready).await;

        let (replaced, linked) = tokio::join!(
            stores.keys.replace(alice, &m.next, m.fresh, m.ready),
            stores.sessions.link(alice, session, m.laptop, m.ready),
        );
        linked.unwrap();

        let ended = stores
            .start_overs
            .request(alice, m.request.id)
            .await
            .unwrap()
            .unwrap()
            .ended
            .map(|ending| ending.how);
        let generation = stores
            .keys
            .current(alice)
            .await
            .unwrap()
            .unwrap()
            .key
            .generation
            .value();
        match replaced.unwrap() {
            KeyReplace::Replaced { .. } => {
                assert_eq!((ended, generation), (Some(StartOverEnd::Used), 2));
            }
            KeyReplace::Refused(StartOverRefusal::NotReady { .. }) => {
                assert_eq!((ended, generation), (None, 1));
            }
            other => panic!("{other:?}"),
        }
    }
}

/// An approved device's cancel racing the write its request allows: exactly one of them lands.
#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_cancel_racing_the_start_over_it_cancels_lets_one_through(pool: PgPool) {
    let stores = Stores::of(&pool);

    for _ in 0..10 {
        let (alice, m) = a_matured_start_over(&pool, &stores).await;

        let (cancelled, replaced) = tokio::join!(
            stores.start_overs.end(
                alice,
                m.request.id,
                m.laptop,
                StartOverEnd::Cancelled,
                m.ready,
            ),
            stores.keys.replace(alice, &m.next, m.fresh, m.ready),
        );

        match (cancelled.unwrap(), replaced.unwrap()) {
            (StartOverEnded::Ended(_), KeyReplace::Refused(StartOverRefusal::Required)) => {
                let held = stores.keys.current(alice).await.unwrap().unwrap();
                assert_eq!(held.key.generation, HistoryGeneration::FIRST);
            }
            (
                StartOverEnded::Refused(StartOverRefusal::Ended),
                KeyReplace::Replaced { closed, .. },
            ) => assert!(closed.is_empty(), "{closed:?}"),
            other => panic!("both or neither: {other:?}"),
        }
    }
}

/// Two devices asking at once, and one device asking twice: one request opens.
#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn two_requests_at_once_open_one(pool: PgPool) {
    let stores = Stores::of(&pool);
    let now = OffsetDateTime::now_utc();

    for _ in 0..10 {
        let alice = a_user(&pool).await;
        let s = stores.view();
        contract::an_account(s, alice, &first_key()).await;
        let (fresh, other) = (
            contract::a_new_device(s, alice, 2).await,
            contract::a_new_device(s, alice, 3).await,
        );
        let (by_fresh, by_other, again) = (
            contract::request_of(s, alice, fresh, now).await,
            contract::request_of(s, alice, other, now).await,
            contract::request_of(s, alice, fresh, now).await,
        );

        let (one, two) = tokio::join!(
            stores.start_overs.open(&by_fresh),
            stores.start_overs.open(&by_other),
        );
        let mut answers = [one.unwrap(), two.unwrap()];
        answers.sort_by_key(|answer| !matches!(answer, StartOverOpened::Opened(_)));
        assert!(
            matches!(answers[0], StartOverOpened::Opened(_)),
            "{answers:?}"
        );
        assert_eq!(
            answers[1],
            StartOverOpened::Refused(StartOverRefusal::Pending)
        );

        let open = stores.start_overs.open_of(alice).await.unwrap().unwrap();
        let mine = if open.device == fresh {
            &again
        } else {
            &by_other
        };
        let (three, four) =
            tokio::join!(stores.start_overs.open(mine), stores.start_overs.open(mine),);
        for answer in [three.unwrap(), four.unwrap()] {
            assert_eq!(answer, StartOverOpened::Existing(open.clone()));
        }
    }
}

/// The asking device revoked as its request opens: the request never outlives the revoke.
#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_revoke_racing_a_request_leaves_no_request_of_a_revoked_device(pool: PgPool) {
    let stores = Stores::of(&pool);

    for _ in 0..10 {
        let alice = a_user(&pool).await;
        let s = stores.view();
        let laptop = contract::an_account(s, alice, &first_key()).await;
        let fresh = contract::a_new_device(s, alice, 2).await;
        let now = OffsetDateTime::now_utc();
        let request = contract::request_of(s, alice, fresh, now).await;

        let (revoked, opened) = tokio::join!(
            stores.devices.revoke(alice, fresh, Some(laptop), now),
            stores.start_overs.open(&request),
        );

        match (revoked.unwrap(), opened.unwrap()) {
            (
                Revocation::Revoked {
                    start_over: Some(cancelled),
                    ..
                },
                StartOverOpened::Opened(_),
            ) => assert_eq!(cancelled.id, request.id),
            (
                Revocation::Revoked {
                    start_over: None, ..
                },
                StartOverOpened::Stale,
            ) => {}
            other => panic!("{other:?}"),
        }
        assert_eq!(stores.start_overs.open_of(alice).await.unwrap(), None);
    }
}

/// The asking device revoked as its matured request is used: one of the two lands.
#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_revoke_racing_the_start_over_lets_one_through(pool: PgPool) {
    let stores = Stores::of(&pool);

    for _ in 0..10 {
        let (alice, m) = a_matured_start_over(&pool, &stores).await;

        let (revoked, replaced) = tokio::join!(
            stores
                .devices
                .revoke(alice, m.fresh, Some(m.laptop), m.ready),
            stores.keys.replace(alice, &m.next, m.fresh, m.ready),
        );

        match (revoked.unwrap(), replaced.unwrap()) {
            (
                Revocation::Revoked {
                    start_over: Some(_),
                    ..
                },
                KeyReplace::Refused(StartOverRefusal::Required),
            )
            | (
                Revocation::Revoked {
                    start_over: None, ..
                },
                KeyReplace::Replaced { .. },
            ) => {}
            other => panic!("{other:?}"),
        }
    }
}

/// An approved device replacing the words as it is revoked: the replacement lands first, or the
/// revoke does and the device, approved no more, writes nothing.
#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_replacement_racing_its_devices_revoke_never_lands_after_it(pool: PgPool) {
    let stores = Stores::of(&pool);
    let next = HistoryKey {
        generation: HistoryGeneration::parse(2).unwrap(),
        ..first_key()
    };

    for _ in 0..10 {
        let alice = a_user(&pool).await;
        let s = stores.view();
        let laptop = contract::an_account(s, alice, &first_key()).await;
        let phone = contract::a_new_device(s, alice, 2).await;
        contract::approved_by_words(s, alice, phone, &first_key()).await;
        let now = OffsetDateTime::now_utc();

        let (replaced, revoked) = tokio::join!(
            stores.keys.replace(alice, &next, phone, now),
            stores.devices.revoke(alice, phone, Some(laptop), now),
        );

        match (replaced.unwrap(), revoked.unwrap()) {
            (KeyReplace::Replaced { .. }, Revocation::Revoked { .. })
            | (KeyReplace::Replaced { .. }, Revocation::Refused(ApprovalRequired)) => {}
            (KeyReplace::Refused(StartOverRefusal::Required), Revocation::Revoked { .. }) => {
                let held = stores.keys.current(alice).await.unwrap().unwrap();
                assert_eq!(held.key, first_key());
            }
            other => panic!("{other:?}"),
        }
    }
}

/// Two devices approved by the words, revoking each other at once: they queue, and the second
/// finds its own device revoked, so no longer approved.
#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn two_approved_devices_revoking_each_other_at_once_revoke_one(pool: PgPool) {
    let stores = Stores::of(&pool);

    for _ in 0..10 {
        let alice = a_user(&pool).await;
        let s = stores.view();
        let laptop = contract::an_account(s, alice, &first_key()).await;
        let phone = contract::a_new_device(s, alice, 3).await;
        contract::approved_by_words(s, alice, phone, &first_key()).await;
        let now = OffsetDateTime::now_utc();

        let (one, two) = tokio::join!(
            stores.devices.revoke(alice, phone, Some(laptop), now),
            stores.devices.revoke(alice, laptop, Some(phone), now),
        );

        let mut answers = [one.unwrap(), two.unwrap()];
        answers.sort_by_key(|answer| matches!(answer, Revocation::Refused(_)));
        assert!(
            matches!(answers[0], Revocation::Revoked { .. }),
            "{answers:?}"
        );
        assert_eq!(answers[1], Revocation::Refused(ApprovalRequired));
        let revoked: Vec<DeviceId> = stores
            .devices
            .list(alice)
            .await
            .unwrap()
            .into_iter()
            .filter(|device| device.is_revoked())
            .map(|device| device.id)
            .collect();
        assert_eq!(revoked.len(), 1);
    }
}
