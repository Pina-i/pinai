//! In-memory fakes of the E2EE ports and the contract every store must satisfy.

use std::sync::Mutex;

use time::OffsetDateTime;

use crate::identity::ActorUri;
use crate::{DeviceId, UserId};

use crate::identity::RemoteActor;
use crate::messaging::GroupSnapshot;
use crate::{CommitId, ConversationId, WelcomeId};

use super::{
    Append, ArchiveCursor, ArchiveEntry, ArchiveSalt, ArchiveStoreError, HistoryArchive,
    NewArchiveEntry,
};
use super::{
    Attestation, Claim, ClaimedKeyPackage, Commit, CommitLog, DeliveryStoreError, Device,
    DeviceAttester, DeviceLabel, DeviceNotifier, DeviceRootKey, Devices, Epoch, KeyPackages,
    KeyStoreError, MlsFederation, MlsNotifier, NewCommit, NewKeyPackage, NewWelcome,
    OutgoingWelcome, RemoteClaimError, RemoteKeyPackages, Revocation, SignedAttestation, Welcome,
    Welcomes,
};

/// Both stores over one state, as KeyPackages mark their device seen.
#[derive(Default)]
pub struct InMemoryKeyDirectory {
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    devices: Vec<Device>,
    packages: Vec<Stashed>,
}

struct Stashed {
    owner: UserId,
    device: DeviceId,
    package: NewKeyPackage,
    claimed_at: Option<OffsetDateTime>,
}

impl Stashed {
    fn is_available(&self, now: OffsetDateTime) -> bool {
        self.claimed_at.is_none() && self.package.expires_at > now
    }
}

impl State {
    fn device_mut(&mut self, id: DeviceId) -> Option<&mut Device> {
        self.devices.iter_mut().find(|d| d.id == id)
    }

    /// The device, recorded if new; `DeviceTaken` when another account holds its id.
    fn record(
        &mut self,
        owner: UserId,
        id: DeviceId,
        label: &DeviceLabel,
    ) -> Result<&mut Device, KeyStoreError> {
        let now = OffsetDateTime::now_utc();
        if self.device_mut(id).is_some_and(|d| d.owner != owner) {
            return Err(KeyStoreError::DeviceTaken);
        }
        if self.device_mut(id).is_none() {
            self.devices.push(Device {
                id,
                owner,
                label: label.clone(),
                paired_at: now,
                last_seen_at: now,
                revoked_at: None,
                attestation: None,
            });
        }
        Ok(self.device_mut(id).expect("just recorded"))
    }
}

#[async_trait::async_trait]
impl Devices for InMemoryKeyDirectory {
    async fn find(&self, id: DeviceId) -> Result<Option<Device>, KeyStoreError> {
        let state = self.state.lock().unwrap();
        Ok(state.devices.iter().find(|d| d.id == id).cloned())
    }

    async fn list(&self, owner: UserId) -> Result<Vec<Device>, KeyStoreError> {
        let state = self.state.lock().unwrap();
        let mut devices: Vec<Device> = state
            .devices
            .iter()
            .filter(|d| d.owner == owner)
            .cloned()
            .collect();
        devices.sort_by_key(|d| (d.revoked_at.is_some(), std::cmp::Reverse(d.last_seen_at)));
        Ok(devices)
    }

    async fn attest(
        &self,
        owner: UserId,
        id: DeviceId,
        label: &DeviceLabel,
        attestation: &Attestation,
    ) -> Result<(), KeyStoreError> {
        let mut state = self.state.lock().unwrap();
        state.record(owner, id, label)?.attestation = Some(attestation.clone());
        Ok(())
    }

    async fn revoke(&self, owner: UserId, id: DeviceId) -> Result<Revocation, KeyStoreError> {
        let mut state = self.state.lock().unwrap();
        let Some(device) = state.device_mut(id).filter(|device| device.owner == owner) else {
            return Ok(Revocation::NotFound);
        };
        if device.revoked_at.is_some() {
            return Ok(Revocation::AlreadyRevoked);
        }
        device.revoked_at = Some(OffsetDateTime::now_utc());
        Ok(Revocation::Revoked)
    }
}

#[async_trait::async_trait]
impl KeyPackages for InMemoryKeyDirectory {
    async fn available(&self, owner: UserId, device: DeviceId) -> Result<usize, KeyStoreError> {
        let now = OffsetDateTime::now_utc();
        let state = self.state.lock().unwrap();
        Ok(state
            .packages
            .iter()
            .filter(|p| p.owner == owner && p.device == device && p.is_available(now))
            .count())
    }

    async fn available_per_device(
        &self,
        owner: UserId,
    ) -> Result<Vec<(DeviceId, usize)>, KeyStoreError> {
        let now = OffsetDateTime::now_utc();
        let state = self.state.lock().unwrap();
        let mut counts: Vec<(DeviceId, usize)> = Vec::new();
        for package in state
            .packages
            .iter()
            .filter(|p| p.owner == owner && p.is_available(now))
        {
            match counts
                .iter_mut()
                .find(|(device, _)| *device == package.device)
            {
                Some((_, count)) => *count += 1,
                None => counts.push((package.device, 1)),
            }
        }
        Ok(counts)
    }

    async fn stash(
        &self,
        owner: UserId,
        device: DeviceId,
        label: &DeviceLabel,
        packages: &[NewKeyPackage],
    ) -> Result<usize, KeyStoreError> {
        let mut state = self.state.lock().unwrap();
        state.record(owner, device, label)?.last_seen_at = OffsetDateTime::now_utc();
        state
            .packages
            .extend(packages.iter().map(|package| Stashed {
                owner,
                device,
                package: package.clone(),
                claimed_at: None,
            }));
        Ok(packages.len())
    }

    async fn claim(
        &self,
        owner: UserId,
        device: Option<DeviceId>,
    ) -> Result<Option<ClaimedKeyPackage>, KeyStoreError> {
        let now = OffsetDateTime::now_utc();
        let mut state = self.state.lock().unwrap();
        let revoked: Vec<DeviceId> = state
            .devices
            .iter()
            .filter(|d| d.is_revoked())
            .map(|d| d.id)
            .collect();
        // Stashed in order, so the first match is the oldest.
        let Some(stashed) = state.packages.iter_mut().find(|p| {
            p.owner == owner
                && device.is_none_or(|d| p.device == d)
                && !revoked.contains(&p.device)
                && p.is_available(now)
        }) else {
            return Ok(None);
        };
        stashed.claimed_at = Some(now);
        Ok(Some(ClaimedKeyPackage {
            device: stashed.device,
            bytes: stashed.package.bytes.clone(),
            expires_at: stashed.package.expires_at,
        }))
    }

    async fn delete_spent(
        &self,
        expired_before: OffsetDateTime,
        claimed_before: OffsetDateTime,
    ) -> Result<usize, KeyStoreError> {
        let mut state = self.state.lock().unwrap();
        let before = state.packages.len();
        state.packages.retain(|p| {
            p.package.expires_at >= expired_before
                && p.claimed_at.is_none_or(|at| at >= claimed_before)
        });
        Ok(before - state.packages.len())
    }
}

/// Signs nothing: the "signature" is the message reversed, under the kid `test-key`.
pub struct PlainAttester;

impl DeviceAttester for PlainAttester {
    fn attest(
        &self,
        actor: &ActorUri,
        device: DeviceId,
        key: &DeviceRootKey,
        expires_at: OffsetDateTime,
    ) -> SignedAttestation {
        let signed_message =
            format!("{actor}\n{device}\n{:?}\n{expires_at}", key.as_bytes()).into_bytes();
        SignedAttestation {
            signature: signed_message.iter().rev().copied().collect(),
            kid: "test-key".to_owned(),
            signed_message,
        }
    }
}

#[derive(Default)]
pub struct RecordingDeviceNotifier {
    joined: Mutex<Vec<(UserId, ActorUri, DeviceId)>>,
    low: Mutex<Vec<UserId>>,
}

impl RecordingDeviceNotifier {
    pub fn joined(&self) -> Vec<(UserId, ActorUri, DeviceId)> {
        self.joined.lock().unwrap().clone()
    }

    pub fn key_packages_low(&self) -> Vec<UserId> {
        self.low.lock().unwrap().clone()
    }
}

impl DeviceNotifier for RecordingDeviceNotifier {
    fn device_joined(
        &self,
        owner: UserId,
        actor: &ActorUri,
        device: DeviceId,
        _key: &DeviceRootKey,
    ) {
        self.joined
            .lock()
            .unwrap()
            .push((owner, actor.clone(), device));
    }

    fn key_packages_low(&self, owner: UserId) {
        self.low.lock().unwrap().push(owner);
    }
}

/// Other instances' answers to claims, by target; an unknown target is a failure.
#[derive(Default)]
pub struct InMemoryRemoteKeyPackages {
    answers: Mutex<Vec<(ActorUri, Claim)>>,
    asked: Mutex<Vec<(ActorUri, ActorUri, Option<DeviceId>)>>,
    asked_each: Mutex<Vec<(ActorUri, ActorUri)>>,
}

impl InMemoryRemoteKeyPackages {
    pub fn with(target: ActorUri, claim: Claim) -> Self {
        Self {
            answers: Mutex::new(vec![(target, claim)]),
            ..Self::default()
        }
    }

    /// `(sender, target, device)` of every claim sent.
    pub fn asked(&self) -> Vec<(ActorUri, ActorUri, Option<DeviceId>)> {
        self.asked.lock().unwrap().clone()
    }

    /// `(sender, target)` of every claim for each device sent.
    pub fn asked_each(&self) -> Vec<(ActorUri, ActorUri)> {
        self.asked_each.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl RemoteKeyPackages for InMemoryRemoteKeyPackages {
    async fn claim(
        &self,
        sender: &ActorUri,
        target: &ActorUri,
        device: Option<DeviceId>,
    ) -> Result<Claim, RemoteClaimError> {
        self.asked
            .lock()
            .unwrap()
            .push((sender.clone(), target.clone(), device));
        self.answers
            .lock()
            .unwrap()
            .iter()
            .find(|(t, _)| t == target)
            .map(|(_, claim)| claim.clone())
            .ok_or_else(|| RemoteClaimError::Unavailable(anyhow::anyhow!("no such peer")))
    }

    async fn claim_each_device(
        &self,
        sender: &ActorUri,
        target: &ActorUri,
    ) -> Result<Vec<Claim>, RemoteClaimError> {
        self.asked_each
            .lock()
            .unwrap()
            .push((sender.clone(), target.clone()));
        let claims: Vec<Claim> = self
            .answers
            .lock()
            .unwrap()
            .iter()
            .filter(|(t, _)| t == target)
            .map(|(_, claim)| claim.clone())
            .collect();
        if claims.is_empty() {
            return Err(RemoteClaimError::Unavailable(anyhow::anyhow!(
                "no such peer"
            )));
        }
        Ok(claims)
    }
}

/// The commit log and the Welcome queue.
#[derive(Default)]
pub struct InMemoryDelivery {
    state: Mutex<DeliveryState>,
}

#[derive(Default)]
struct DeliveryState {
    commits: Vec<Commit>,
    /// Each Welcome with when it was claimed.
    welcomes: Vec<(Welcome, Option<OffsetDateTime>)>,
}

#[async_trait::async_trait]
impl CommitLog for InMemoryDelivery {
    async fn append(&self, commit: &NewCommit) -> Result<Append, DeliveryStoreError> {
        let mut state = self.state.lock().unwrap();
        if let Some(winner) = state
            .commits
            .iter()
            .find(|c| c.conversation == commit.conversation && c.epoch == commit.epoch)
        {
            return Ok(Append::Taken(winner.clone()));
        }
        let stored = Commit {
            id: CommitId::generate(),
            conversation: commit.conversation,
            epoch: commit.epoch,
            blob: commit.blob.clone(),
            proposer: commit.proposer.clone(),
            created_at: OffsetDateTime::now_utc(),
        };
        state.commits.push(stored.clone());
        Ok(Append::Stored(stored))
    }

    async fn since(
        &self,
        conversation: ConversationId,
        after: Epoch,
        limit: usize,
    ) -> Result<Vec<Commit>, DeliveryStoreError> {
        let state = self.state.lock().unwrap();
        let mut commits: Vec<Commit> = state
            .commits
            .iter()
            .filter(|c| c.conversation == conversation && c.epoch > after)
            .cloned()
            .collect();
        commits.sort_by_key(|c| c.epoch);
        commits.truncate(limit);
        Ok(commits)
    }
}

#[async_trait::async_trait]
impl Welcomes for InMemoryDelivery {
    async fn deposit(&self, welcome: &NewWelcome) -> Result<Welcome, DeliveryStoreError> {
        let deposited = Welcome {
            id: WelcomeId::generate(),
            recipient: welcome.recipient,
            device: welcome.device,
            conversation: welcome.conversation,
            blob: welcome.blob.clone(),
            created_at: OffsetDateTime::now_utc(),
        };
        let mut state = self.state.lock().unwrap();
        state.welcomes.push((deposited.clone(), None));
        Ok(deposited)
    }

    async fn claim(
        &self,
        recipient: UserId,
        device: DeviceId,
    ) -> Result<Vec<Welcome>, DeliveryStoreError> {
        let now = OffsetDateTime::now_utc();
        let mut state = self.state.lock().unwrap();
        Ok(state
            .welcomes
            .iter_mut()
            .filter(|(w, claimed)| {
                w.recipient == recipient && w.device == device && claimed.is_none()
            })
            .map(|(w, claimed)| {
                *claimed = Some(now);
                w.clone()
            })
            .collect())
    }

    async fn delete_claimed_before(
        &self,
        cutoff: OffsetDateTime,
    ) -> Result<usize, DeliveryStoreError> {
        let mut state = self.state.lock().unwrap();
        let before = state.welcomes.len();
        state
            .welcomes
            .retain(|(_, claimed)| claimed.is_none_or(|at| at >= cutoff));
        Ok(before - state.welcomes.len())
    }
}

#[derive(Default)]
pub struct RecordingMlsNotifier {
    committed: Mutex<Vec<(UserId, Commit)>>,
    ready: Mutex<Vec<(UserId, Welcome)>>,
}

impl RecordingMlsNotifier {
    pub fn committed(&self) -> Vec<(UserId, Commit)> {
        self.committed.lock().unwrap().clone()
    }

    pub fn welcomes_ready(&self) -> Vec<(UserId, Welcome)> {
        self.ready.lock().unwrap().clone()
    }
}

impl MlsNotifier for RecordingMlsNotifier {
    fn committed(&self, to: UserId, commit: &Commit) {
        self.committed.lock().unwrap().push((to, commit.clone()));
    }

    fn welcome_ready(&self, to: UserId, welcome: &Welcome) {
        self.ready.lock().unwrap().push((to, welcome.clone()));
    }
}

/// What the Delivery Service sent to other instances.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SentMls {
    Commit {
        from: ActorUri,
        to: ActorUri,
        commit: Commit,
        roster: Option<GroupSnapshot>,
    },
    Welcome {
        from: ActorUri,
        to: ActorUri,
        welcome: OutgoingWelcome,
    },
}

#[derive(Default)]
pub struct RecordingMlsFederation {
    sent: Mutex<Vec<SentMls>>,
}

impl RecordingMlsFederation {
    pub fn sent(&self) -> Vec<SentMls> {
        self.sent.lock().unwrap().clone()
    }
}

impl MlsFederation for RecordingMlsFederation {
    fn send_commit(
        &self,
        from: &ActorUri,
        to: &[ActorUri],
        commit: &Commit,
        roster: Option<&GroupSnapshot>,
    ) {
        let mut sent = self.sent.lock().unwrap();
        sent.extend(to.iter().map(|member| SentMls::Commit {
            from: from.clone(),
            to: member.clone(),
            commit: commit.clone(),
            roster: roster.cloned(),
        }));
    }

    fn send_welcome(&self, from: &ActorUri, to: &RemoteActor, welcome: &OutgoingWelcome) {
        self.sent.lock().unwrap().push(SentMls::Welcome {
            from: from.clone(),
            to: to.actor_uri.clone(),
            welcome: welcome.clone(),
        });
    }
}

/// Each account's archive entries, and salts.
#[derive(Default)]
pub struct InMemoryArchive {
    state: Mutex<ArchiveState>,
}

#[derive(Default)]
struct ArchiveState {
    entries: Vec<(UserId, ArchiveEntry)>,
    salts: Vec<(UserId, ArchiveSalt)>,
}

#[async_trait::async_trait]
impl HistoryArchive for InMemoryArchive {
    async fn store(
        &self,
        owner: UserId,
        entries: &[NewArchiveEntry],
    ) -> Result<usize, ArchiveStoreError> {
        // One upload, one moment: its entries share their `created_at`.
        let now = OffsetDateTime::now_utc();
        let mut state = self.state.lock().unwrap();
        let mut stored = 0;
        for entry in entries {
            if state
                .entries
                .iter()
                .any(|(o, e)| *o == owner && e.id == entry.id)
            {
                continue;
            }
            state.entries.push((
                owner,
                ArchiveEntry {
                    id: entry.id,
                    conversation: entry.conversation,
                    ciphertext: entry.ciphertext.clone(),
                    nonce: entry.nonce.clone(),
                    client_message_id: entry.client_message_id.clone(),
                    created_at: now,
                },
            ));
            stored += 1;
        }
        Ok(stored)
    }

    async fn page(
        &self,
        owner: UserId,
        after: Option<ArchiveCursor>,
        limit: usize,
    ) -> Result<Vec<ArchiveEntry>, ArchiveStoreError> {
        let state = self.state.lock().unwrap();
        let mut entries: Vec<ArchiveEntry> = state
            .entries
            .iter()
            .filter(|(o, e)| {
                *o == owner && after.is_none_or(|c| (e.created_at, e.id) < (c.created_at, c.id))
            })
            .map(|(_, e)| e.clone())
            .collect();
        entries.sort_by_key(|e| std::cmp::Reverse((e.created_at, e.id)));
        entries.truncate(limit);
        Ok(entries)
    }

    async fn clear(&self, owner: UserId) -> Result<usize, ArchiveStoreError> {
        let mut state = self.state.lock().unwrap();
        let before = state.entries.len();
        state.entries.retain(|(o, _)| *o != owner);
        Ok(before - state.entries.len())
    }

    async fn salt(&self, owner: UserId) -> Result<Option<ArchiveSalt>, ArchiveStoreError> {
        let state = self.state.lock().unwrap();
        Ok(state
            .salts
            .iter()
            .find(|(o, _)| *o == owner)
            .map(|(_, salt)| salt.clone()))
    }

    async fn set_salt_once(
        &self,
        owner: UserId,
        salt: &ArchiveSalt,
    ) -> Result<ArchiveSalt, ArchiveStoreError> {
        let mut state = self.state.lock().unwrap();
        if let Some((_, held)) = state.salts.iter().find(|(o, _)| *o == owner) {
            return Ok(held.clone());
        }
        state.salts.push((owner, salt.clone()));
        Ok(salt.clone())
    }
}

/// What every store of devices and KeyPackages must do. Timestamps are whole seconds, which
/// every store keeps exactly.
pub mod contract {
    use time::Duration;

    use super::*;
    use crate::e2ee::{DeviceKind, KeyPackageBytes};

    fn at(offset: Duration) -> OffsetDateTime {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        OffsetDateTime::from_unix_timestamp(now).unwrap() + offset
    }

    fn label(name: &str) -> DeviceLabel {
        DeviceLabel {
            name: name.to_owned(),
            kind: DeviceKind::Laptop,
        }
    }

    fn attestation(key: u8) -> Attestation {
        Attestation {
            root_key: DeviceRootKey::parse(&[key; 32]).unwrap(),
            signature: vec![key; 64],
            kid: "key-1".to_owned(),
            issued_at: at(Duration::ZERO),
            expires_at: at(Duration::days(365)),
        }
    }

    fn package(byte: u8, expires_in: Duration) -> NewKeyPackage {
        NewKeyPackage {
            bytes: KeyPackageBytes::parse(vec![byte; 4]).unwrap(),
            expires_at: at(expires_in),
        }
    }

    fn fresh(byte: u8) -> NewKeyPackage {
        package(byte, Duration::days(30))
    }

    pub async fn a_registered_device_is_found_and_listed_with_its_attestation(
        devices: &dyn Devices,
        alice: UserId,
    ) {
        let (id, attested) = (DeviceId::generate(), attestation(1));

        devices
            .attest(alice, id, &label("Firefox on Linux"), &attested)
            .await
            .unwrap();

        let device = devices.find(id).await.unwrap().expect("recorded");
        assert_eq!(
            (device.owner, &device.label, device.revoked_at),
            (alice, &label("Firefox on Linux"), None)
        );
        assert_eq!(device.attestation, Some(attested));
        assert_eq!(devices.list(alice).await.unwrap(), vec![device]);
        assert_eq!(devices.find(DeviceId::generate()).await.unwrap(), None);
    }

    pub async fn registering_again_replaces_the_attestation_and_keeps_the_label(
        devices: &dyn Devices,
        alice: UserId,
    ) {
        let id = DeviceId::generate();
        devices
            .attest(alice, id, &label("first"), &attestation(1))
            .await
            .unwrap();

        let renewed = attestation(2);
        devices
            .attest(alice, id, &label("second"), &renewed)
            .await
            .unwrap();

        let device = devices.find(id).await.unwrap().unwrap();
        assert_eq!(
            (device.label, device.attestation),
            (label("first"), Some(renewed))
        );
    }

    pub async fn devices_are_listed_active_first_then_most_recently_seen(
        devices: &dyn Devices,
        packages: &dyn KeyPackages,
        alice: UserId,
        bob: UserId,
    ) {
        let (old, seen, recent) = (
            DeviceId::generate(),
            DeviceId::generate(),
            DeviceId::generate(),
        );
        for id in [old, seen, recent] {
            devices
                .attest(alice, id, &label("laptop"), &attestation(1))
                .await
                .unwrap();
        }
        devices
            .attest(bob, DeviceId::generate(), &label("bob's"), &attestation(1))
            .await
            .unwrap();
        devices.revoke(alice, recent).await.unwrap();
        packages
            .stash(alice, seen, &label("laptop"), &[fresh(1)])
            .await
            .unwrap();

        let listed: Vec<DeviceId> = devices
            .list(alice)
            .await
            .unwrap()
            .iter()
            .map(|d| d.id)
            .collect();

        assert_eq!(listed, vec![seen, old, recent]);
    }

    pub async fn a_device_is_revoked_once_and_only_by_its_owner(
        devices: &dyn Devices,
        alice: UserId,
        bob: UserId,
    ) {
        let id = DeviceId::generate();
        devices
            .attest(alice, id, &label("laptop"), &attestation(1))
            .await
            .unwrap();

        assert_eq!(devices.revoke(bob, id).await.unwrap(), Revocation::NotFound);
        assert_eq!(
            devices.revoke(alice, id).await.unwrap(),
            Revocation::Revoked
        );
        assert_eq!(
            devices.revoke(alice, id).await.unwrap(),
            Revocation::AlreadyRevoked
        );
        assert_eq!(
            devices.revoke(alice, DeviceId::generate()).await.unwrap(),
            Revocation::NotFound
        );
        assert!(
            devices
                .find(id)
                .await
                .unwrap()
                .unwrap()
                .revoked_at
                .is_some()
        );
    }

    pub async fn a_stash_counts_per_device_what_is_neither_claimed_nor_expired(
        packages: &dyn KeyPackages,
        alice: UserId,
        bob: UserId,
    ) {
        let (laptop, phone) = (DeviceId::generate(), DeviceId::generate());
        packages
            .stash(
                alice,
                laptop,
                &label("laptop"),
                &[fresh(1), fresh(2), fresh(3)],
            )
            .await
            .unwrap();
        let stored = packages
            .stash(
                alice,
                phone,
                &label("phone"),
                &[fresh(4), package(5, -Duration::minutes(1))],
            )
            .await
            .unwrap();
        packages
            .stash(bob, DeviceId::generate(), &label("bob's"), &[fresh(6)])
            .await
            .unwrap();
        packages.claim(alice, Some(laptop)).await.unwrap();

        let mut per_device = packages.available_per_device(alice).await.unwrap();
        per_device.sort_by_key(|(_, count)| *count);

        assert_eq!(stored, 2);
        assert_eq!(packages.available(alice, laptop).await.unwrap(), 2);
        assert_eq!(per_device, vec![(phone, 1), (laptop, 2)]);
    }

    pub async fn stashing_records_a_new_device_and_marks_a_known_one_seen(
        devices: &dyn Devices,
        packages: &dyn KeyPackages,
        alice: UserId,
    ) {
        let id = DeviceId::generate();
        packages
            .stash(alice, id, &label("Chrome on Android"), &[fresh(1)])
            .await
            .unwrap();
        let recorded = devices.find(id).await.unwrap().expect("recorded");

        packages
            .stash(alice, id, &label("another name"), &[fresh(2)])
            .await
            .unwrap();

        let seen = devices.find(id).await.unwrap().unwrap();
        assert_eq!(
            (recorded.owner, &recorded.label, &recorded.attestation),
            (alice, &label("Chrome on Android"), &None)
        );
        assert_eq!(seen.label, label("Chrome on Android"));
        assert!(seen.last_seen_at >= recorded.last_seen_at);
    }

    pub async fn a_claim_hands_out_the_oldest_package_once(
        packages: &dyn KeyPackages,
        alice: UserId,
    ) {
        let (device, oldest) = (DeviceId::generate(), fresh(1));
        for stashed in [oldest.clone(), fresh(2)] {
            packages
                .stash(alice, device, &label("laptop"), &[stashed])
                .await
                .unwrap();
        }

        let first = packages.claim(alice, Some(device)).await.unwrap();
        let second = packages.claim(alice, Some(device)).await.unwrap();

        assert_eq!(
            first,
            Some(ClaimedKeyPackage {
                device,
                bytes: oldest.bytes,
                expires_at: oldest.expires_at,
            })
        );
        assert_eq!(second.map(|claimed| claimed.bytes), Some(fresh(2).bytes));
        assert_eq!(packages.claim(alice, Some(device)).await.unwrap(), None);
    }

    pub async fn a_claim_for_any_device_names_the_one_it_took_from(
        packages: &dyn KeyPackages,
        alice: UserId,
        bob: UserId,
    ) {
        let (empty, stocked) = (DeviceId::generate(), DeviceId::generate());
        packages
            .stash(
                alice,
                empty,
                &label("laptop"),
                &[package(1, -Duration::minutes(1))],
            )
            .await
            .unwrap();
        packages
            .stash(alice, stocked, &label("phone"), &[fresh(2)])
            .await
            .unwrap();
        packages
            .stash(bob, DeviceId::generate(), &label("bob's"), &[fresh(3)])
            .await
            .unwrap();

        let claimed = packages
            .claim(alice, None)
            .await
            .unwrap()
            .expect("one left");

        assert_eq!((claimed.device, claimed.bytes), (stocked, fresh(2).bytes));
        assert_eq!(packages.claim(alice, None).await.unwrap(), None);
    }

    pub async fn a_claim_never_hands_out_a_revoked_devices_packages(
        devices: &dyn Devices,
        packages: &dyn KeyPackages,
        alice: UserId,
    ) {
        let (revoked, laptop) = (DeviceId::generate(), DeviceId::generate());
        packages
            .stash(alice, revoked, &label("stolen phone"), &[fresh(1)])
            .await
            .unwrap();
        packages
            .stash(alice, laptop, &label("laptop"), &[fresh(2)])
            .await
            .unwrap();
        devices.revoke(alice, revoked).await.unwrap();

        let any = packages.claim(alice, None).await.unwrap();
        let pinned = packages.claim(alice, Some(revoked)).await.unwrap();

        assert_eq!(any.map(|claimed| claimed.device), Some(laptop));
        assert_eq!(pinned, None);
        assert_eq!(packages.claim(alice, None).await.unwrap(), None);
    }

    pub async fn a_device_of_another_account_is_neither_attested_nor_stashed_for(
        devices: &dyn Devices,
        packages: &dyn KeyPackages,
        alice: UserId,
        bob: UserId,
    ) {
        let id = DeviceId::generate();
        devices
            .attest(alice, id, &label("alice's"), &attestation(1))
            .await
            .unwrap();
        let before = devices.find(id).await.unwrap();

        let attested = devices
            .attest(bob, id, &label("bob's"), &attestation(2))
            .await;
        let stashed = packages.stash(bob, id, &label("bob's"), &[fresh(1)]).await;

        assert!(
            matches!(attested, Err(KeyStoreError::DeviceTaken)),
            "{attested:?}"
        );
        assert!(
            matches!(stashed, Err(KeyStoreError::DeviceTaken)),
            "{stashed:?}"
        );
        assert_eq!(devices.find(id).await.unwrap(), before);
        assert_eq!(packages.available(bob, id).await.unwrap(), 0);
    }

    pub async fn spent_packages_are_deleted_once_expired_or_claimed_past_the_cutoff(
        packages: &dyn KeyPackages,
        alice: UserId,
    ) {
        let device = DeviceId::generate();
        packages
            .stash(
                alice,
                device,
                &label("laptop"),
                &[package(1, -Duration::minutes(1)), fresh(2)],
            )
            .await
            .unwrap();
        packages
            .stash(alice, device, &label("laptop"), &[fresh(3)])
            .await
            .unwrap();
        packages.claim(alice, Some(device)).await.unwrap();

        let expired = packages
            .delete_spent(at(Duration::ZERO), at(-Duration::days(1)))
            .await
            .unwrap();
        let claimed = packages
            .delete_spent(at(Duration::ZERO), at(Duration::minutes(1)))
            .await
            .unwrap();

        assert_eq!((expired, claimed), (1, 1));
        assert_eq!(packages.available(alice, device).await.unwrap(), 1);
    }

    fn commit(conversation: ConversationId, epoch: i64, by: &ActorUri, byte: u8) -> NewCommit {
        NewCommit {
            conversation,
            epoch: Epoch::parse(epoch).unwrap(),
            blob: crate::e2ee::CommitBlob::parse(vec![byte; 8]).unwrap(),
            proposer: by.clone(),
        }
    }

    fn welcome(recipient: UserId, device: DeviceId, byte: u8) -> NewWelcome {
        NewWelcome {
            recipient,
            device,
            conversation: ConversationId::generate(),
            blob: crate::e2ee::WelcomeBlob::parse(vec![byte; 8]).unwrap(),
        }
    }

    fn stored(append: Append) -> Commit {
        match append {
            Append::Stored(commit) => commit,
            Append::Taken(winner) => panic!("epoch {} was taken", winner.epoch.value()),
        }
    }

    /// `group` and `other` are conversations the store may reference.
    pub async fn commits_are_caught_up_in_epoch_order_after_an_epoch(
        log: &dyn CommitLog,
        group: ConversationId,
        other: ConversationId,
        alice: &ActorUri,
    ) {
        let mut appended = Vec::new();
        for epoch in [1, 3, 2] {
            appended.push(stored(
                log.append(&commit(group, epoch, alice, epoch as u8))
                    .await
                    .unwrap(),
            ));
        }
        log.append(&commit(other, 1, alice, 9)).await.unwrap();
        appended.sort_by_key(|c| c.epoch);

        let all = log
            .since(group, Epoch::parse(0).unwrap(), 10)
            .await
            .unwrap();
        let after_one = log
            .since(group, Epoch::parse(1).unwrap(), 10)
            .await
            .unwrap();
        let first_two = log.since(group, Epoch::parse(0).unwrap(), 2).await.unwrap();

        assert_eq!(all, appended);
        assert_eq!(after_one, appended[1..].to_vec());
        assert_eq!(first_two, appended[..2].to_vec());
        assert_eq!(
            (
                appended[0].proposer.clone(),
                appended[0].blob.as_bytes().to_vec()
            ),
            (alice.clone(), vec![1; 8])
        );
    }

    pub async fn a_commit_at_a_taken_epoch_loses_to_the_one_there(
        log: &dyn CommitLog,
        group: ConversationId,
        alice: &ActorUri,
        bob: &ActorUri,
    ) {
        let first = stored(log.append(&commit(group, 4, alice, 1)).await.unwrap());

        let second = log.append(&commit(group, 4, bob, 2)).await.unwrap();

        assert_eq!(second, Append::Taken(first.clone()));
        assert_eq!(
            log.since(group, Epoch::parse(0).unwrap(), 10)
                .await
                .unwrap(),
            vec![first]
        );
    }

    pub async fn a_welcome_is_claimed_once_and_only_by_its_device(
        welcomes: &dyn Welcomes,
        alice: UserId,
        bob: UserId,
    ) {
        let (laptop, phone) = (DeviceId::generate(), DeviceId::generate());
        let mut for_laptop = Vec::new();
        for byte in [1, 2] {
            for_laptop.push(
                welcomes
                    .deposit(&welcome(alice, laptop, byte))
                    .await
                    .unwrap(),
            );
        }
        let for_phone = welcomes.deposit(&welcome(alice, phone, 3)).await.unwrap();
        welcomes.deposit(&welcome(bob, laptop, 4)).await.unwrap();

        let mut claimed = welcomes.claim(alice, laptop).await.unwrap();
        claimed.sort_by_key(|w| w.blob.as_bytes().to_vec());
        let again = welcomes.claim(alice, laptop).await.unwrap();

        assert_eq!(claimed, for_laptop);
        assert_eq!(again, Vec::new());
        assert_eq!(welcomes.claim(alice, phone).await.unwrap(), vec![for_phone]);
    }

    pub async fn claimed_welcomes_are_deleted_once_past_the_cutoff(
        welcomes: &dyn Welcomes,
        alice: UserId,
    ) {
        let (laptop, phone) = (DeviceId::generate(), DeviceId::generate());
        welcomes.deposit(&welcome(alice, laptop, 1)).await.unwrap();
        let waiting = welcomes.deposit(&welcome(alice, phone, 2)).await.unwrap();
        welcomes.claim(alice, laptop).await.unwrap();

        let within = welcomes
            .delete_claimed_before(at(-Duration::minutes(1)))
            .await
            .unwrap();
        let past = welcomes
            .delete_claimed_before(at(Duration::minutes(1)))
            .await
            .unwrap();

        assert_eq!((within, past), (0, 1));
        assert_eq!(welcomes.claim(alice, phone).await.unwrap(), vec![waiting]);
    }

    fn archived(conversation: ConversationId, byte: u8) -> NewArchiveEntry {
        NewArchiveEntry {
            id: crate::MessageId::generate(),
            conversation,
            ciphertext: vec![byte; 20],
            nonce: crate::e2ee::ArchiveNonce::parse(&[byte; 12]).unwrap(),
            client_message_id: Some(format!("client-{byte}")),
        }
    }

    /// `conversation` is one the store may reference.
    pub async fn an_entry_is_archived_once_per_owner(
        archive: &dyn HistoryArchive,
        alice: UserId,
        bob: UserId,
        conversation: ConversationId,
    ) {
        let entries = [archived(conversation, 1), archived(conversation, 2)];

        let first = archive.store(alice, &entries).await.unwrap();
        let again = archive.store(alice, &entries).await.unwrap();
        let bobs = archive.store(bob, &entries[..1]).await.unwrap();

        assert_eq!((first, again, bobs), (2, 0, 1));
        let page = archive.page(alice, None, 10).await.unwrap();
        let one = page
            .iter()
            .find(|e| e.id == entries[0].id)
            .expect("archived");
        assert_eq!(
            (
                &one.conversation,
                &one.ciphertext,
                &one.nonce,
                &one.client_message_id
            ),
            (
                &conversation,
                &entries[0].ciphertext,
                &entries[0].nonce,
                &entries[0].client_message_id
            )
        );
        assert_eq!(page.len(), 2);
    }

    pub async fn the_archive_pages_newest_first_before_a_cursor(
        archive: &dyn HistoryArchive,
        alice: UserId,
        conversation: ConversationId,
    ) {
        let older: Vec<NewArchiveEntry> = (1..=3).map(|b| archived(conversation, b)).collect();
        let newer: Vec<NewArchiveEntry> = (4..=5).map(|b| archived(conversation, b)).collect();
        archive.store(alice, &older).await.unwrap();
        archive.store(alice, &newer).await.unwrap();

        let all = archive.page(alice, None, 10).await.unwrap();
        let first = archive.page(alice, None, 2).await.unwrap();
        let rest = archive
            .page(alice, Some(first[1].cursor()), 10)
            .await
            .unwrap();

        let ids = |entries: &[ArchiveEntry]| {
            let mut ids: Vec<crate::MessageId> = entries.iter().map(|e| e.id).collect();
            ids.sort();
            ids
        };
        let expected = |entries: &[NewArchiveEntry]| {
            let mut ids: Vec<crate::MessageId> = entries.iter().map(|e| e.id).collect();
            ids.sort();
            ids
        };
        assert_eq!(all.len(), 5);
        assert_eq!(ids(&all[..2]), expected(&newer));
        assert_eq!(ids(&all[2..]), expected(&older));
        assert!(
            all[0].id > all[1].id,
            "one upload's entries go by id, descending"
        );
        assert_eq!(first, all[..2].to_vec());
        assert_eq!(rest, all[2..].to_vec());
    }

    pub async fn clearing_an_archive_deletes_its_owners_entries_only(
        archive: &dyn HistoryArchive,
        alice: UserId,
        bob: UserId,
        conversation: ConversationId,
    ) {
        archive
            .store(
                alice,
                &[archived(conversation, 1), archived(conversation, 2)],
            )
            .await
            .unwrap();
        archive
            .store(bob, &[archived(conversation, 3)])
            .await
            .unwrap();

        let cleared = archive.clear(alice).await.unwrap();

        assert_eq!(cleared, 2);
        assert!(archive.page(alice, None, 10).await.unwrap().is_empty());
        assert_eq!(archive.page(bob, None, 10).await.unwrap().len(), 1);
    }

    pub async fn the_first_salt_set_is_kept(archive: &dyn HistoryArchive, alice: UserId) {
        let (first, second) = (
            ArchiveSalt::parse(&[1; 16]).unwrap(),
            ArchiveSalt::parse(&[2; 16]).unwrap(),
        );

        let unset = archive.salt(alice).await.unwrap();
        let set = archive.set_salt_once(alice, &first).await.unwrap();
        let kept = archive.set_salt_once(alice, &second).await.unwrap();

        assert_eq!((unset, &set, &kept), (None, &first, &first));
        assert_eq!(archive.salt(alice).await.unwrap(), Some(first));
    }
}

#[cfg(test)]
mod tests;
