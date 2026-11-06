use domain::e2ee::testing::{PlainEd25519Verifier, contract, plain_signature};
use domain::e2ee::{
    ApprovalBy, ApprovalFacts, ApprovalMessageBody, ApprovalPublicKey, ApprovalRequest,
    ApprovalRequests, Approve, Attestation, CheckedApproval, Device, DeviceApprovals, DeviceLabel,
    DeviceRootKey, Devices, HistoryCheckValue, HistoryGeneration, HistoryKey, HistoryKeys,
    HistorySalt, HpkeKeyWrite, Opened, Post, RequestRefusal, approval_bytes, may_approve,
};
use domain::identity::ActorUri;
use domain::{DeviceId, UserId};
use infrastructure::postgres::{PgApprovalRequests, PgDeviceApprovals, PgDevices, PgHistoryKeys};
use sqlx::PgPool;
use time::{Duration, OffsetDateTime};

use super::a_user;

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn approvals_are_stored_once_per_approver_and_listed_by_owner(pool: PgPool) {
    let (alice, bob) = (a_user(&pool).await, a_user(&pool).await);
    contract::approvals_are_stored_once_per_approver_and_listed_by_owner(
        &PgDevices::new(pool.clone()),
        &PgDeviceApprovals::new(pool.clone()),
        &PgHistoryKeys::new(pool),
        alice,
        bob,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn an_approval_is_stored_only_while_what_it_was_checked_on_holds(pool: PgPool) {
    let alice = a_user(&pool).await;
    contract::an_approval_is_stored_only_while_what_it_was_checked_on_holds(
        &PgDevices::new(pool.clone()),
        &PgDeviceApprovals::new(pool.clone()),
        &PgHistoryKeys::new(pool),
        alice,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn revoking_a_device_drops_the_approvals_it_signed(pool: PgPool) {
    let alice = a_user(&pool).await;
    contract::revoking_a_device_drops_the_approvals_it_signed(
        &PgDevices::new(pool.clone()),
        &PgDeviceApprovals::new(pool),
        alice,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_new_root_key_drops_the_devices_approvals_and_those_it_signed(pool: PgPool) {
    let alice = a_user(&pool).await;
    contract::a_new_root_key_drops_the_devices_approvals_and_those_it_signed(
        &PgDevices::new(pool.clone()),
        &PgDeviceApprovals::new(pool),
        alice,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_new_generation_drops_the_approvals_made_under_older_ones(pool: PgPool) {
    let (alice, bob) = (a_user(&pool).await, a_user(&pool).await);
    contract::a_new_generation_drops_the_approvals_made_under_older_ones(
        &PgDevices::new(pool.clone()),
        &PgDeviceApprovals::new(pool.clone()),
        &PgHistoryKeys::new(pool),
        alice,
        bob,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn opening_a_request_closes_the_devices_open_one(pool: PgPool) {
    let alice = a_user(&pool).await;
    contract::opening_a_request_closes_the_devices_open_one(
        &PgApprovalRequests::new(pool.clone()),
        &PgDevices::new(pool),
        alice,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn an_account_opens_a_limited_number_of_requests_an_hour(pool: PgPool) {
    let (alice, bob) = (a_user(&pool).await, a_user(&pool).await);
    contract::an_account_opens_a_limited_number_of_requests_an_hour(
        &PgApprovalRequests::new(pool.clone()),
        &PgDevices::new(pool),
        alice,
        bob,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn the_first_message_from_another_device_binds_the_request(pool: PgPool) {
    let alice = a_user(&pool).await;
    contract::the_first_message_from_another_device_binds_the_request(
        &PgApprovalRequests::new(pool.clone()),
        &PgDevices::new(pool),
        alice,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_request_takes_a_dozen_messages_while_open_and_ends_once(pool: PgPool) {
    let (alice, bob) = (a_user(&pool).await, a_user(&pool).await);
    contract::a_request_takes_a_dozen_messages_while_open_and_ends_once(
        &PgApprovalRequests::new(pool.clone()),
        &PgDevices::new(pool),
        alice,
        bob,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn revoking_a_device_closes_the_requests_it_asks_or_answers(pool: PgPool) {
    let alice = a_user(&pool).await;
    contract::revoking_a_device_closes_the_requests_it_asks_or_answers(
        &PgApprovalRequests::new(pool.clone()),
        &PgDevices::new(pool),
        alice,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn requests_opened_before_the_cutoff_are_deleted_with_their_messages(pool: PgPool) {
    let alice = a_user(&pool).await;
    contract::requests_opened_before_the_cutoff_are_deleted_with_their_messages(
        &PgApprovalRequests::new(pool.clone()),
        &PgDevices::new(pool),
        alice,
    )
    .await;
}

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(OffsetDateTime::now_utc().unix_timestamp()).unwrap()
}

fn actor() -> ActorUri {
    ActorUri::parse("https://idp.test/users/alice_t3st0").unwrap()
}

fn attestation(key: u8) -> Attestation {
    Attestation {
        root_key: DeviceRootKey::parse(&[key; 32]).unwrap(),
        signature: vec![key; 64],
        kid: "key-1".to_owned(),
        issued_at: now(),
        expires_at: now() + Duration::days(365),
    }
}

/// An attested device of `owner`'s, its root key made of `key`s.
async fn a_device(devices: &PgDevices, owner: UserId, key: u8) -> DeviceId {
    let id = DeviceId::generate();
    devices
        .attest(
            owner,
            id,
            &DeviceLabel::unknown(),
            None,
            &attestation(key),
            &HpkeKeyWrite::Clear,
        )
        .await
        .unwrap();
    id
}

async fn found(devices: &PgDevices, id: DeviceId) -> Device {
    devices.find(id).await.unwrap().unwrap()
}

fn root_key(device: &Device) -> DeviceRootKey {
    device.attestation.as_ref().unwrap().root_key.clone()
}

/// `signer`'s approval of `approved`, checked on the devices as they are now.
async fn by_device(devices: &PgDevices, signer: DeviceId, approved: DeviceId) -> CheckedApproval {
    let (signer, approved_device) = (found(devices, signer).await, found(devices, approved).await);
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
    .unwrap()
}

fn history_key(generation: i64, byte: u8) -> HistoryKey {
    HistoryKey {
        generation: HistoryGeneration::parse(generation).unwrap(),
        salt: HistorySalt::parse(&[byte; 16]).unwrap(),
        check_value: HistoryCheckValue::parse(&[byte; 32]).unwrap(),
        approval_public_key: ApprovalPublicKey::parse(&[byte; 32]).unwrap(),
    }
}

/// `device` approved by `key`'s passphrase, checked as it is now.
async fn by_passphrase(devices: &PgDevices, device: DeviceId, key: &HistoryKey) -> CheckedApproval {
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
    may_approve(device, by, signature, facts, &PlainEd25519Verifier).unwrap()
}

/// A new root key for `id`, decided on the device as it is now.
async fn rotate(devices: &PgDevices, owner: UserId, id: DeviceId, key: u8) {
    let read = devices.find(id).await.unwrap();
    devices
        .attest(
            owner,
            id,
            &DeviceLabel::unknown(),
            read.as_ref(),
            &attestation(key),
            &HpkeKeyWrite::Clear,
        )
        .await
        .unwrap();
}

async fn approvals_of(approvals: &PgDeviceApprovals, owner: UserId, device: DeviceId) -> usize {
    approvals
        .of_owner(owner)
        .await
        .unwrap()
        .into_iter()
        .filter(|approval| approval.device == device)
        .count()
}

/// Two devices answering a request at once: one takes it, the other is turned away.
#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn two_devices_answering_at_once_bind_the_request_once(pool: PgPool) {
    let (devices, requests) = (
        PgDevices::new(pool.clone()),
        PgApprovalRequests::new(pool.clone()),
    );
    let alice = a_user(&pool).await;
    let laptop = found(&devices, a_device(&devices, alice, 1).await).await;
    let body = ApprovalMessageBody::parse(vec![1; 32]).unwrap();

    for _ in 0..10 {
        let phone = found(&devices, a_device(&devices, alice, 2).await).await;
        let tablet = found(&devices, a_device(&devices, alice, 3).await).await;
        let request = ApprovalRequest::open_for(&laptop, now()).unwrap();
        requests.open(&request).await.unwrap();

        let (one, other) = tokio::join!(
            requests.post(alice, request.id, &phone, &body, now()),
            requests.post(alice, request.id, &tablet, &body, now()),
        );

        let outcomes = [one.unwrap(), other.unwrap()];
        let bound: Vec<_> = outcomes
            .iter()
            .filter_map(|post| match post {
                Post::Posted { request, bound, .. } => bound.then_some(request.approver),
                Post::Refused(_) | Post::Stale => None,
            })
            .collect();
        assert_eq!(bound.len(), 1, "{outcomes:?}");
        assert!(
            outcomes.contains(&Post::Refused(RequestRefusal::Taken)),
            "{outcomes:?}"
        );
        assert_eq!(
            requests.open_of(alice, now()).await.unwrap()[0].approver,
            bound[0]
        );
        requests
            .delete_opened_before(now() + Duration::minutes(1))
            .await
            .unwrap();
    }
}

/// Eleven requests opened at once: the account's lock counts them one after the other.
#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn requests_opened_at_once_never_pass_the_hourly_limit(pool: PgPool) {
    let (devices, requests) = (
        PgDevices::new(pool.clone()),
        PgApprovalRequests::new(pool.clone()),
    );
    let alice = a_user(&pool).await;
    let mut asking = Vec::new();
    for key in 0..11 {
        let device = found(&devices, a_device(&devices, alice, key).await).await;
        asking.push(ApprovalRequest::open_for(&device, now()).unwrap());
    }

    let opened = futures_util::future::join_all(asking.iter().map(|r| requests.open(r))).await;

    let refused = opened
        .into_iter()
        .filter(|outcome| *outcome.as_ref().unwrap() == Opened::TooMany)
        .count();
    assert_eq!(refused, 1);
}

/// A revoke racing an approval the device signs: refused, or written then dropped by the revoke.
#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn an_approval_racing_its_signers_revoke_is_never_kept(pool: PgPool) {
    let (devices, approvals) = (
        PgDevices::new(pool.clone()),
        PgDeviceApprovals::new(pool.clone()),
    );
    let alice = a_user(&pool).await;

    for _ in 0..10 {
        let (laptop, phone) = (
            a_device(&devices, alice, 1).await,
            a_device(&devices, alice, 2).await,
        );
        let checked = by_device(&devices, laptop, phone).await;

        let (approved, revoked) = tokio::join!(
            approvals.approve(alice, &checked),
            devices.revoke(alice, laptop, Some(laptop), time::OffsetDateTime::now_utc()),
        );
        approved.unwrap();
        revoked.unwrap();

        assert_eq!(approvals_of(&approvals, alice, phone).await, 0);
    }
}

/// The approved device revoked meanwhile: the write is refused once the revoke is in, so what is
/// answered is what is held.
#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn an_approval_racing_the_approved_devices_revoke_is_written_only_before_it(pool: PgPool) {
    let (devices, approvals) = (
        PgDevices::new(pool.clone()),
        PgDeviceApprovals::new(pool.clone()),
    );
    let alice = a_user(&pool).await;

    for _ in 0..10 {
        let (laptop, phone) = (
            a_device(&devices, alice, 1).await,
            a_device(&devices, alice, 2).await,
        );
        let checked = by_device(&devices, laptop, phone).await;

        let (approved, revoked) = tokio::join!(
            approvals.approve(alice, &checked),
            devices.revoke(alice, phone, Some(phone), time::OffsetDateTime::now_utc()),
        );
        revoked.unwrap();

        let held = approvals_of(&approvals, alice, phone).await;
        match approved.unwrap() {
            Approve::Recorded { .. } => assert_eq!(held, 1),
            Approve::Stale => assert_eq!(held, 0),
            Approve::AlreadyHeld => panic!("approved once"),
        }
    }
}

/// A new root key racing an approval — of the approved device, or of the one signing: refused, or
/// written then dropped by the rotation.
#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn an_approval_racing_a_root_key_rotation_is_never_kept(pool: PgPool) {
    let (devices, approvals) = (
        PgDevices::new(pool.clone()),
        PgDeviceApprovals::new(pool.clone()),
    );
    let alice = a_user(&pool).await;

    for round in 0..20 {
        let (laptop, phone) = (
            a_device(&devices, alice, 1).await,
            a_device(&devices, alice, 2).await,
        );
        let checked = by_device(&devices, laptop, phone).await;
        let rotated = if round % 2 == 0 { phone } else { laptop };

        let (approved, ()) = tokio::join!(
            approvals.approve(alice, &checked),
            rotate(&devices, alice, rotated, 9),
        );
        approved.unwrap();

        assert_eq!(approvals_of(&approvals, alice, phone).await, 0, "{round}");
    }
}

/// A new generation racing an approval by the passphrase of the one before: refused, or written
/// then dropped with the old generation.
#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_passphrase_approval_racing_a_new_generation_is_never_kept(pool: PgPool) {
    let (devices, approvals, keys) = (
        PgDevices::new(pool.clone()),
        PgDeviceApprovals::new(pool.clone()),
        PgHistoryKeys::new(pool.clone()),
    );

    for _ in 0..10 {
        let alice = a_user(&pool).await;
        let laptop = a_device(&devices, alice, 1).await;
        let first = history_key(1, 1);
        keys.replace(alice, &first, laptop, time::OffsetDateTime::now_utc())
            .await
            .unwrap();
        let checked = by_passphrase(&devices, laptop, &first).await;
        let second = history_key(2, 2);

        let (approved, replaced) = tokio::join!(
            approvals.approve(alice, &checked),
            keys.replace(alice, &second, laptop, time::OffsetDateTime::now_utc()),
        );
        approved.unwrap();
        replaced.unwrap();

        assert_eq!(approvals_of(&approvals, alice, laptop).await, 0);
    }
}

/// A revoke racing the device's own request: refused, or opened then closed by the revoke — never
/// left open for a revoked device.
#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_request_racing_its_devices_revoke_is_never_left_open(pool: PgPool) {
    let (devices, requests) = (
        PgDevices::new(pool.clone()),
        PgApprovalRequests::new(pool.clone()),
    );
    let alice = a_user(&pool).await;

    for _ in 0..10 {
        let laptop = found(&devices, a_device(&devices, alice, 1).await).await;
        let request = ApprovalRequest::open_for(&laptop, now()).unwrap();

        let (opened, revoked) = tokio::join!(
            requests.open(&request),
            devices.revoke(
                alice,
                laptop.id,
                Some(laptop.id),
                time::OffsetDateTime::now_utc()
            ),
        );
        revoked.unwrap();

        assert!(matches!(
            opened.unwrap(),
            Opened::Opened { .. } | Opened::Stale
        ));
        assert!(
            requests
                .open_of(alice, now())
                .await
                .unwrap()
                .iter()
                .all(|open| open.device != laptop.id)
        );
    }
}

/// A revoke racing the answer that would bind a request to the device: refused, or bound then
/// closed by the revoke — never left open with a revoked device answering it.
#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn an_answer_racing_its_devices_revoke_never_leaves_the_request_to_it(pool: PgPool) {
    let (devices, requests) = (
        PgDevices::new(pool.clone()),
        PgApprovalRequests::new(pool.clone()),
    );
    let alice = a_user(&pool).await;
    let body = ApprovalMessageBody::parse(vec![1; 32]).unwrap();

    for _ in 0..10 {
        let laptop = found(&devices, a_device(&devices, alice, 1).await).await;
        let phone = found(&devices, a_device(&devices, alice, 2).await).await;
        let request = ApprovalRequest::open_for(&laptop, now()).unwrap();
        requests.open(&request).await.unwrap();

        let (posted, revoked) = tokio::join!(
            requests.post(alice, request.id, &phone, &body, now()),
            devices.revoke(
                alice,
                phone.id,
                Some(phone.id),
                time::OffsetDateTime::now_utc()
            ),
        );
        revoked.unwrap();

        assert!(matches!(
            posted.unwrap(),
            Post::Posted { bound: true, .. } | Post::Stale
        ));
        assert!(
            requests
                .open_of(alice, now())
                .await
                .unwrap()
                .iter()
                .all(|open| open.approver != Some(phone.id))
        );
    }
}
