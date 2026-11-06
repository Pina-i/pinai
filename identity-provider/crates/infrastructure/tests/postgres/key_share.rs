use domain::e2ee::testing::contract::{self, ShareStores};
use domain::e2ee::testing::hpke_key;
use domain::e2ee::{
    ApprovalPublicKey, Attestation, CheckedShare, Deposit, DeviceLabel, DeviceRootKey, Devices,
    HistoryCheckValue, HistoryGeneration, HistoryKey, HistoryKeys, HistorySalt, HpkeKeyWrite,
    KeyShares,
};
use domain::{DeviceId, UserId};
use infrastructure::postgres::{PgDeviceApprovals, PgDevices, PgHistoryKeys, PgKeyShares};
use sqlx::PgPool;
use time::{Duration, OffsetDateTime};

use super::a_user;

/// The stores of one database.
struct Stores {
    devices: PgDevices,
    approvals: PgDeviceApprovals,
    keys: PgHistoryKeys,
    shares: PgKeyShares,
}

impl Stores {
    fn of(pool: &PgPool) -> Self {
        Self {
            devices: PgDevices::new(pool.clone()),
            approvals: PgDeviceApprovals::new(pool.clone()),
            keys: PgHistoryKeys::new(pool.clone()),
            shares: PgKeyShares::new(pool.clone()),
        }
    }

    fn view(&self) -> ShareStores<'_> {
        ShareStores {
            devices: &self.devices,
            approvals: &self.approvals,
            keys: &self.keys,
            shares: &self.shares,
        }
    }
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_share_is_stored_once_per_recipient_and_generation_and_read_by_its_recipient(
    pool: PgPool,
) {
    let (alice, bob) = (a_user(&pool).await, a_user(&pool).await);
    contract::a_share_is_stored_once_per_recipient_and_generation_and_read_by_its_recipient(
        Stores::of(&pool).view(),
        alice,
        bob,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_holder_that_did_not_approve_the_recipient_shares_nothing(pool: PgPool) {
    let alice = a_user(&pool).await;
    contract::a_holder_that_did_not_approve_the_recipient_shares_nothing(
        Stores::of(&pool).view(),
        alice,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_share_is_stored_only_while_what_it_was_checked_on_holds(pool: PgPool) {
    let alice = a_user(&pool).await;
    contract::a_share_is_stored_only_while_what_it_was_checked_on_holds(
        Stores::of(&pool).view(),
        alice,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_new_generation_deletes_the_accounts_shares(pool: PgPool) {
    let (alice, bob) = (a_user(&pool).await, a_user(&pool).await);
    contract::a_new_generation_deletes_the_accounts_shares(Stores::of(&pool).view(), alice, bob)
        .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn revoking_a_device_deletes_the_shares_it_sent_or_was_sent(pool: PgPool) {
    let alice = a_user(&pool).await;
    contract::revoking_a_device_deletes_the_shares_it_sent_or_was_sent(
        Stores::of(&pool).view(),
        alice,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_new_root_key_or_hpke_key_deletes_the_shares_it_no_longer_fits(pool: PgPool) {
    let alice = a_user(&pool).await;
    contract::a_new_root_key_or_hpke_key_deletes_the_shares_it_no_longer_fits(
        Stores::of(&pool).view(),
        alice,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn the_recipient_holding_the_generation_deletes_its_share(pool: PgPool) {
    let alice = a_user(&pool).await;
    contract::the_recipient_holding_the_generation_deletes_its_share(
        Stores::of(&pool).view(),
        alice,
    )
    .await;
}

/// The shares the account holds, whatever their generation.
async fn shares_of(pool: &PgPool, owner: UserId) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM history_key_shares WHERE user_id = $1")
        .bind(owner.as_uuid())
        .fetch_one(pool)
        .await
        .unwrap()
}

/// A fresh account and the laptop's share for its phone, checked and not deposited yet.
async fn a_share(pool: &PgPool, stores: &Stores) -> (UserId, CheckedShare) {
    let alice = a_user(pool).await;
    (
        alice,
        contract::a_share_to_deposit(stores.view(), alice).await,
    )
}

fn second() -> HistoryKey {
    HistoryKey {
        generation: HistoryGeneration::parse(2).unwrap(),
        salt: HistorySalt::parse(&[2; 16]).unwrap(),
        check_value: HistoryCheckValue::parse(&[2; 32]).unwrap(),
        approval_public_key: ApprovalPublicKey::parse(&[3; 32]).unwrap(),
    }
}

/// A new generation racing a share of the one before: refused, or written then deleted with it.
#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_share_racing_a_new_generation_is_never_kept(pool: PgPool) {
    let stores = Stores::of(&pool);

    for _ in 0..10 {
        let (alice, share) = a_share(&pool, &stores).await;
        let next = second();

        let (deposited, replaced) = tokio::join!(
            stores.shares.deposit(alice, &share),
            stores.keys.replace(
                alice,
                &next,
                share.sender(),
                time::OffsetDateTime::now_utc()
            ),
        );
        deposited.unwrap();
        replaced.unwrap();

        assert_eq!(shares_of(&pool, alice).await, 0);
    }
}

/// The recipient revoked as the share is written: refused, or written then deleted by the revoke.
#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_share_racing_its_recipients_revoke_is_never_kept(pool: PgPool) {
    let stores = Stores::of(&pool);

    for _ in 0..10 {
        let (alice, share) = a_share(&pool, &stores).await;

        let (deposited, revoked) = tokio::join!(
            stores.shares.deposit(alice, &share),
            stores.devices.revoke(
                alice,
                share.recipient(),
                Some(share.recipient()),
                time::OffsetDateTime::now_utc()
            ),
        );
        revoked.unwrap();

        assert!(matches!(
            deposited.unwrap(),
            Deposit::Stored | Deposit::Stale
        ));
        assert_eq!(shares_of(&pool, alice).await, 0);
    }
}

/// The recipient saying it holds the generation as the share is written: refused, or written then
/// deleted by the report.
#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_share_racing_its_recipients_report_is_never_kept(pool: PgPool) {
    let stores = Stores::of(&pool);

    for _ in 0..10 {
        let (alice, share) = a_share(&pool, &stores).await;

        let (deposited, reported) = tokio::join!(
            stores.shares.deposit(alice, &share),
            stores
                .devices
                .hold_history_key(alice, share.recipient(), share.generation()),
        );
        deposited.unwrap();
        reported.unwrap();

        assert_eq!(shares_of(&pool, alice).await, 0);
    }
}

/// `id` registered again as it is now: its root key made of `root`s, its HPKE key of `hpke`s.
async fn reregister(devices: &PgDevices, owner: UserId, id: DeviceId, root: u8, hpke: u8) {
    let now =
        OffsetDateTime::from_unix_timestamp(OffsetDateTime::now_utc().unix_timestamp()).unwrap();
    let attestation = Attestation {
        root_key: DeviceRootKey::parse(&[root; 32]).unwrap(),
        signature: vec![root; 64],
        kid: "key-1".to_owned(),
        issued_at: now,
        expires_at: now + Duration::days(365),
    };
    let read = devices.find(id).await.unwrap();
    devices
        .attest(
            owner,
            id,
            &DeviceLabel::unknown(),
            read.as_ref(),
            &attestation,
            &HpkeKeyWrite::Set(hpke_key(hpke)),
        )
        .await
        .unwrap();
}

/// What a change racing a share does to the share's devices, as `a_share_to_deposit` makes them:
/// the laptop's root key and HPKE key are made of 1s, the phone's of 2s.
#[derive(Debug, Clone, Copy)]
enum Change {
    RevokeTheSender,
    RotateTheSender,
    RotateTheRecipient,
    ResealTheRecipient,
}

async fn change(stores: &Stores, owner: UserId, share: &CheckedShare, change: Change) {
    let devices = &stores.devices;
    match change {
        Change::RevokeTheSender => {
            devices
                .revoke(
                    owner,
                    share.sender(),
                    Some(share.sender()),
                    time::OffsetDateTime::now_utc(),
                )
                .await
                .unwrap();
        }
        Change::RotateTheSender => reregister(devices, owner, share.sender(), 9, 1).await,
        Change::RotateTheRecipient => reregister(devices, owner, share.recipient(), 9, 2).await,
        Change::ResealTheRecipient => reregister(devices, owner, share.recipient(), 2, 20).await,
    }
}

/// A revoke or a new key of either device racing a share: refused, or written then deleted by
/// the change.
#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_share_racing_a_change_of_its_devices_is_never_kept(pool: PgPool) {
    let stores = Stores::of(&pool);

    for which in [
        Change::RevokeTheSender,
        Change::RotateTheSender,
        Change::RotateTheRecipient,
        Change::ResealTheRecipient,
    ] {
        for _ in 0..5 {
            let (alice, share) = a_share(&pool, &stores).await;

            let (deposited, ()) = tokio::join!(
                stores.shares.deposit(alice, &share),
                change(&stores, alice, &share, which),
            );
            deposited.unwrap();

            assert_eq!(shares_of(&pool, alice).await, 0, "{which:?}");
        }
    }
}

/// A new root key, or a revoke, of the device that approved the sender, as a share is written:
/// the two never wait on each other, and the share is stored only before the link drops — a
/// later drop doesn't delete it.
#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_share_racing_a_change_of_its_chains_approver_ends_one_way_or_the_other(pool: PgPool) {
    let stores = Stores::of(&pool);

    for round in 0..20 {
        let alice = a_user(&pool).await;
        let (share, approver) = contract::a_share_through_an_approver(stores.view(), alice).await;

        let (deposited, ()) = tokio::join!(stores.shares.deposit(alice, &share), async {
            if round % 2 == 0 {
                reregister(&stores.devices, alice, approver, 9, 1).await;
            } else {
                stores
                    .devices
                    .revoke(
                        alice,
                        approver,
                        Some(approver),
                        time::OffsetDateTime::now_utc(),
                    )
                    .await
                    .unwrap();
            }
        });

        let held = shares_of(&pool, alice).await;
        match deposited.unwrap() {
            Deposit::Stored => assert_eq!(held, 1, "{round}"),
            Deposit::Stale => assert_eq!(held, 0, "{round}"),
            Deposit::AlreadyHeld => panic!("deposited once"),
        }
    }
}
