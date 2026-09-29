use std::sync::Arc;

use domain::DeviceId;
use domain::e2ee::testing::{
    InMemoryKeyDirectory, InMemoryRemoteKeyPackages, PlainAttester, RecordingDeviceNotifier,
};
use domain::e2ee::{
    ATTESTATION_LIFETIME, Claim, ClaimedKeyPackage, DeviceAttester, DeviceKind, DeviceLabel,
    DeviceRootKey, Devices, KeyDirectoryError, KeyPackageBytes, KeyPackagePolicy,
    KeyPackageRefusal, KeyPackages, NewKeyPackage,
};
use domain::identity::testing::{InMemoryAccounts, account, remote_actor};
use domain::identity::{Account, ActorUri, InstanceOrigin, RemoteActor, Requester};
use time::{Duration, OffsetDateTime};

use super::*;

struct World {
    alice: Account,
    bob: Account,
    carol: RemoteActor,
    carols_claim: Claim,
    store: Arc<InMemoryKeyDirectory>,
    notifier: Arc<RecordingDeviceNotifier>,
    remote: Arc<InMemoryRemoteKeyPackages>,
    register: RegisterDevice,
    list: ListDevices,
    revoke: RevokeDevice,
    upload: UploadKeyPackages,
    claim: ClaimKeyPackage,
    status: KeyPackageStatus,
    sweep: SweepKeyPackages,
}

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(OffsetDateTime::now_utc().unix_timestamp()).unwrap()
}

fn policy() -> KeyPackagePolicy {
    KeyPackagePolicy {
        cap_per_device: 10,
        refill_threshold: 3,
        max_lifetime: Duration::days(30),
    }
}

fn key(byte: u8) -> DeviceRootKey {
    DeviceRootKey::parse(&[byte; 32]).unwrap()
}

fn package(byte: u8) -> NewKeyPackage {
    NewKeyPackage {
        bytes: KeyPackageBytes::parse(vec![byte; 4]).unwrap(),
        expires_at: now() + Duration::days(7),
    }
}

fn batch(n: u8) -> Vec<NewKeyPackage> {
    (1..=n).map(package).collect()
}

fn phone() -> DeviceLabel {
    DeviceLabel {
        name: "Chrome on Android".to_owned(),
        kind: DeviceKind::Phone,
    }
}

fn world() -> World {
    let (alice, bob) = (account("alice"), account("bob"));
    let carol = remote_actor("carol_k2m9x@idp.carol.test");
    let carols_claim = Claim {
        package: ClaimedKeyPackage {
            device: DeviceId::generate(),
            bytes: KeyPackageBytes::parse(vec![42; 8]).unwrap(),
            expires_at: now() + Duration::days(3),
        },
        remaining: 20,
        needs_refill: false,
    };
    let accounts = Arc::new(InMemoryAccounts::with([alice.clone(), bob.clone()]));
    let store = Arc::new(InMemoryKeyDirectory::default());
    let notifier = Arc::new(RecordingDeviceNotifier::default());
    let remote = Arc::new(InMemoryRemoteKeyPackages::with(
        carol.actor_uri.clone(),
        carols_claim.clone(),
    ));
    World {
        register: RegisterDevice::new(
            accounts.clone(),
            store.clone(),
            Arc::new(PlainAttester),
            notifier.clone(),
        ),
        list: ListDevices::new(store.clone()),
        revoke: RevokeDevice::new(store.clone()),
        upload: UploadKeyPackages::new(policy(), store.clone(), store.clone()),
        claim: ClaimKeyPackage::new(
            InstanceOrigin::parse("http://localhost:8080").unwrap(),
            policy(),
            accounts,
            store.clone(),
            remote.clone(),
        ),
        status: KeyPackageStatus::new(policy(), store.clone()),
        sweep: SweepKeyPackages::new(store.clone()),
        alice,
        bob,
        carol,
        carols_claim,
        store,
        notifier,
        remote,
    }
}

impl World {
    async fn upload(&self, owner: &Account, device: DeviceId, packages: Vec<NewKeyPackage>) {
        self.upload
            .execute(owner.id, device, phone(), packages, now())
            .await
            .unwrap();
    }

    async fn claim_as(
        &self,
        requester: Requester,
        target: &ActorUri,
        device: Option<DeviceId>,
    ) -> Result<Claim, KeyDirectoryError> {
        self.claim.execute(&requester, target, device).await
    }
}

#[tokio::test]
async fn a_first_registration_attests_the_key_and_tells_the_owners_other_devices() {
    let w = world();
    let (device, at) = (DeviceId::generate(), now());

    let registered = w
        .register
        .execute(w.alice.id, device, key(1), at)
        .await
        .unwrap();

    let expires_at = at + ATTESTATION_LIFETIME;
    assert_eq!(
        registered.signed,
        PlainAttester.attest(&w.alice.actor_uri, device, &key(1), expires_at)
    );
    assert_eq!(
        (registered.issued_at, registered.expires_at),
        (at, expires_at)
    );
    let stored = w.store.find(device).await.unwrap().expect("recorded");
    let attestation = stored.attestation.expect("attested");
    assert_eq!(
        (stored.owner, stored.label, attestation.root_key),
        (w.alice.id, DeviceLabel::unknown(), key(1))
    );
    assert_eq!(
        (
            attestation.signature,
            attestation.kid,
            attestation.expires_at
        ),
        (
            registered.signed.signature,
            registered.signed.kid,
            expires_at
        )
    );
    assert_eq!(
        w.notifier.joined(),
        vec![(w.alice.id, w.alice.actor_uri.clone(), device)]
    );
}

#[tokio::test]
async fn registering_again_renews_or_rotates_the_key_without_telling_anyone() {
    let w = world();
    let (device, later) = (DeviceId::generate(), now() + Duration::days(300));
    w.register
        .execute(w.alice.id, device, key(1), now())
        .await
        .unwrap();

    w.register
        .execute(w.alice.id, device, key(1), later)
        .await
        .unwrap();
    let renewed = w.store.find(device).await.unwrap().unwrap();
    w.register
        .execute(w.alice.id, device, key(2), now())
        .await
        .unwrap();
    let rotated = w.store.find(device).await.unwrap().unwrap();

    assert_eq!(
        renewed.attestation.unwrap().expires_at,
        later + ATTESTATION_LIFETIME
    );
    assert_eq!(rotated.attestation.unwrap().root_key, key(2));
    assert_eq!(w.notifier.joined().len(), 1, "only the first registration");
}

#[tokio::test]
async fn the_owner_lists_its_own_devices() {
    let w = world();
    let (laptop, phone) = (DeviceId::generate(), DeviceId::generate());
    w.register
        .execute(w.alice.id, laptop, key(1), now())
        .await
        .unwrap();
    w.upload(&w.alice, phone, batch(1)).await;
    w.upload(&w.bob, DeviceId::generate(), batch(1)).await;

    let listed: Vec<DeviceId> = w
        .list
        .execute(w.alice.id)
        .await
        .unwrap()
        .iter()
        .map(|d| d.id)
        .collect();

    assert_eq!(listed, vec![phone, laptop]);
}

#[tokio::test]
async fn a_device_is_revoked_by_its_owner_and_not_found_by_anyone_else() {
    let w = world();
    let device = DeviceId::generate();
    w.upload(&w.alice, device, batch(1)).await;

    let by_bob = w.revoke.execute(w.bob.id, device).await;
    let unknown = w.revoke.execute(w.alice.id, DeviceId::generate()).await;
    w.revoke.execute(w.alice.id, device).await.unwrap();
    let again = w.revoke.execute(w.alice.id, device).await;

    assert!(
        matches!(by_bob, Err(KeyDirectoryError::DeviceNotFound)),
        "{by_bob:?}"
    );
    assert!(
        matches!(unknown, Err(KeyDirectoryError::DeviceNotFound)),
        "{unknown:?}"
    );
    assert!(again.is_ok(), "{again:?}");
    assert!(
        w.store
            .find(device)
            .await
            .unwrap()
            .unwrap()
            .revoked_at
            .is_some()
    );
}

#[tokio::test]
async fn an_upload_stashes_the_batch_and_names_a_new_device() {
    let w = world();
    let device = DeviceId::generate();

    let uploaded = w
        .upload
        .execute(w.alice.id, device, phone(), batch(2), now())
        .await
        .unwrap();
    let again = w
        .upload
        .execute(w.alice.id, device, DeviceLabel::unknown(), batch(3), now())
        .await
        .unwrap();

    assert_eq!(
        (uploaded, again),
        (
            Uploaded {
                uploaded: 2,
                available_after: 2
            },
            Uploaded {
                uploaded: 3,
                available_after: 5
            }
        )
    );
    let stored = w.store.find(device).await.unwrap().unwrap();
    assert_eq!((stored.owner, stored.label), (w.alice.id, phone()));
}

#[tokio::test]
async fn an_upload_past_the_cap_or_the_lifetime_is_refused_whole() {
    let w = world();
    let device = DeviceId::generate();
    w.upload(&w.alice, device, batch(9)).await;
    let mut too_long = batch(2);
    too_long[1].expires_at = now() + Duration::days(31);

    let full = w
        .upload
        .execute(w.alice.id, device, phone(), batch(2), now())
        .await;
    let long = w
        .upload
        .execute(w.alice.id, DeviceId::generate(), phone(), too_long, now())
        .await;

    assert!(
        matches!(
            full,
            Err(KeyDirectoryError::Refused(KeyPackageRefusal::StashFull {
                available: 9,
                uploading: 2,
                cap: 10
            }))
        ),
        "{full:?}"
    );
    assert!(
        matches!(
            long,
            Err(KeyDirectoryError::Refused(KeyPackageRefusal::LivesTooLong(
                1
            )))
        ),
        "{long:?}"
    );
    assert_eq!(w.store.available(w.alice.id, device).await.unwrap(), 9);
    assert_eq!(
        w.store
            .available_per_device(w.alice.id)
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn a_claim_for_a_local_account_hands_out_its_oldest_package_and_says_when_to_refill() {
    let w = world();
    let device = DeviceId::generate();
    w.upload(&w.alice, device, vec![package(1)]).await;
    w.upload(&w.alice, device, batch(3)).await;

    let claim = w
        .claim_as(Requester::User(w.bob.id), &w.alice.actor_uri, None)
        .await
        .unwrap();

    assert_eq!(
        (
            claim.package.device,
            claim.package.bytes,
            claim.remaining,
            claim.needs_refill
        ),
        (device, package(1).bytes, 3, true)
    );
    assert!(w.remote.asked().is_empty());
}

#[tokio::test]
async fn a_claim_for_a_pinned_device_takes_from_that_device_only() {
    let w = world();
    let (laptop, phone) = (DeviceId::generate(), DeviceId::generate());
    w.upload(&w.alice, laptop, batch(5)).await;
    w.upload(&w.alice, phone, vec![package(9)]).await;

    let claim = w
        .claim_as(Requester::User(w.alice.id), &w.alice.actor_uri, Some(phone))
        .await
        .unwrap();
    let emptied = w
        .claim_as(Requester::User(w.alice.id), &w.alice.actor_uri, Some(phone))
        .await;

    assert_eq!(
        (claim.package.device, claim.package.bytes, claim.remaining),
        (phone, package(9).bytes, 0)
    );
    assert!(
        matches!(emptied, Err(KeyDirectoryError::NoKeyPackage)),
        "{emptied:?}"
    );
}

#[tokio::test]
async fn a_claim_names_no_user_or_no_package_when_there_is_none() {
    let w = world();
    let nobody = ActorUri::parse("http://localhost:8080/users/nobody_t3st0").unwrap();

    let unknown = w.claim_as(Requester::User(w.alice.id), &nobody, None).await;
    let empty = w
        .claim_as(Requester::User(w.alice.id), &w.bob.actor_uri, None)
        .await;

    assert!(
        matches!(unknown, Err(KeyDirectoryError::UserNotFound)),
        "{unknown:?}"
    );
    assert!(
        matches!(empty, Err(KeyDirectoryError::NoKeyPackage)),
        "{empty:?}"
    );
}

#[tokio::test]
async fn a_users_claim_for_an_account_elsewhere_is_asked_of_its_instance() {
    let w = world();
    let phone = DeviceId::generate();

    let claim = w
        .claim_as(Requester::User(w.alice.id), &w.carol.actor_uri, Some(phone))
        .await
        .unwrap();

    assert_eq!(claim, w.carols_claim);
    assert_eq!(
        w.remote.asked(),
        vec![(
            w.alice.actor_uri.clone(),
            w.carol.actor_uri.clone(),
            Some(phone)
        )]
    );
}

#[tokio::test]
async fn a_peer_claims_only_for_accounts_of_this_instance() {
    let w = world();
    let peer = ActorUri::parse("https://idp.carol.test/actor").unwrap();
    w.upload(&w.alice, DeviceId::generate(), batch(1)).await;

    let local = w
        .claim_as(Requester::Peer(peer.clone()), &w.alice.actor_uri, None)
        .await;
    let relayed = w
        .claim_as(Requester::Peer(peer), &w.carol.actor_uri, None)
        .await;

    assert!(local.is_ok(), "{local:?}");
    assert!(
        matches!(relayed, Err(KeyDirectoryError::PeerMustTargetLocal)),
        "{relayed:?}"
    );
    assert!(w.remote.asked().is_empty());
}

#[tokio::test]
async fn the_stash_status_counts_each_device_against_the_threshold() {
    let w = world();
    let (laptop, phone) = (DeviceId::generate(), DeviceId::generate());
    w.upload(&w.alice, laptop, batch(5)).await;
    w.upload(&w.alice, phone, batch(2)).await;

    let mut status = w.status.execute(w.alice.id).await.unwrap();
    status.devices.sort_by_key(|d| d.available);

    assert_eq!(
        status,
        StashStatus {
            devices: vec![
                DeviceStash {
                    device: phone,
                    available: 2,
                    needs_refill: true
                },
                DeviceStash {
                    device: laptop,
                    available: 5,
                    needs_refill: false
                },
            ],
            refill_threshold: 3,
            cap: 10,
        }
    );
}

#[tokio::test]
async fn spent_packages_are_swept_once_their_grace_is_over() {
    let w = world();
    let device = DeviceId::generate();
    w.upload(&w.alice, device, batch(3)).await;
    w.claim_as(Requester::User(w.bob.id), &w.alice.actor_uri, None)
        .await
        .unwrap();

    let within_grace = w.sweep.execute(now()).await.unwrap();
    let after_grace = w.sweep.execute(now() + Duration::days(2)).await.unwrap();

    assert_eq!((within_grace, after_grace), (0, 1));
    assert_eq!(w.store.available(w.alice.id, device).await.unwrap(), 2);
}

#[tokio::test]
async fn a_revoked_device_neither_renews_its_attestation_nor_publishes_key_packages() {
    let w = world();
    let device = DeviceId::generate();
    w.register
        .execute(w.alice.id, device, key(1), now())
        .await
        .unwrap();
    w.revoke.execute(w.alice.id, device).await.unwrap();

    let renewal = w.register.execute(w.alice.id, device, key(1), now()).await;
    let upload = w
        .upload
        .execute(w.alice.id, device, phone(), batch(1), now())
        .await;

    assert!(
        matches!(renewal, Err(KeyDirectoryError::DeviceRevoked)),
        "{:?}",
        renewal.err()
    );
    assert!(
        matches!(upload, Err(KeyDirectoryError::DeviceRevoked)),
        "{upload:?}"
    );
    assert_eq!(w.store.available(w.alice.id, device).await.unwrap(), 0);
}

#[tokio::test]
async fn a_device_id_another_account_holds_is_neither_registered_nor_stocked() {
    let w = world();
    let device = DeviceId::generate();
    w.register
        .execute(w.alice.id, device, key(1), now())
        .await
        .unwrap();
    let alices = w.store.find(device).await.unwrap();

    let registered = w.register.execute(w.bob.id, device, key(2), now()).await;
    let uploaded = w
        .upload
        .execute(w.bob.id, device, phone(), batch(1), now())
        .await;

    assert!(
        matches!(registered, Err(KeyDirectoryError::DeviceTaken)),
        "{:?}",
        registered.err()
    );
    assert!(
        matches!(uploaded, Err(KeyDirectoryError::DeviceTaken)),
        "{uploaded:?}"
    );
    assert_eq!(w.store.find(device).await.unwrap(), alices);
    assert_eq!(w.notifier.joined().len(), 1, "alice's registration only");
}
