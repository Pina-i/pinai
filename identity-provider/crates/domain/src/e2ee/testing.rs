//! In-memory fakes of the E2EE ports and the contract every store must satisfy.

mod approval;
mod key_share;
mod start_over;

use std::sync::{Arc, Mutex};

use time::OffsetDateTime;

use crate::identity::ActorUri;
use crate::{DeviceId, UserId};

use crate::identity::RemoteActor;
use crate::messaging::GroupSnapshot;
use crate::{CommitId, ConversationId, WelcomeId};

pub use approval::{InMemoryApprovalRequests, RecordingDeviceTrustNotifier, SentTrust};
pub use key_share::sealed_share;

use super::{
    Append, ArchiveCursor, ArchiveEntry, ArchiveStoreError, Archived, HeldHistoryKey,
    HistoryArchive, HistoryGeneration, HistoryKey, HistoryKeys, Holding, KeyReplace,
    NewArchiveEntry, check_history_generation,
};
use super::{
    Approval, Approver, ArchiveError, DeviceTrust, Ed25519PublicKey, KeyGate, KeyShare,
    StartOverEnd, StartOverEnding, StartOverRequest, may_replace_history_key, may_revoke,
};
use super::{
    Attest, Attestation, AttestationExpiry, Claim, ClaimedKeyPackage, Commit, CommitLog,
    DeliveryStoreError, Device, DeviceAttester, DeviceLabel, DeviceNotifier, DeviceRootKey,
    Devices, Ed25519Signature, Ed25519Verifier, Epoch, HeldHpkeKey, HpkeKeyWrite, HpkePublicKey,
    KeyPackages, KeyStoreError, MlsFederation, MlsNotifier, NewCommit, NewKeyPackage, NewWelcome,
    OutgoingWelcome, RemoteClaimError, RemoteKeyPackages, Revocation, SignedAttestation,
    SignedHpkeKey, UnverifiedHpkeKey, Welcome, Welcomes,
};
use crate::auth::Sessions;
use crate::auth::testing::InMemorySessions;

/// The approvals of each account's devices, which a revoke, a new root key and a new generation
/// drop: shared by the directory and the history keys, as one database holds them.
type Approvals = Arc<Mutex<Vec<(UserId, Approval)>>>;

/// The key shares of each account's devices, which a revoke, a new root key or HPKE key, a report
/// and a new generation drop: shared as the approvals are.
type Shares = Arc<Mutex<Vec<(UserId, KeyShare)>>>;

/// The start over requests, which a revoke and a new generation end: shared as the approvals are.
type StartOvers = Arc<Mutex<Vec<StartOverRequest>>>;

/// The devices, their KeyPackages and their approvals over one state, as KeyPackages mark their
/// device seen.
#[derive(Default)]
pub struct InMemoryKeyDirectory {
    /// Shared with the history keys, which decide a new generation on the devices.
    state: Arc<Mutex<State>>,
    /// Whose current generation a device's report, or a passphrase's approval, is checked
    /// against; none, every one is stale.
    history: Option<Arc<InMemoryArchive>>,
    approvals: Approvals,
    shares: Shares,
    start_overs: StartOvers,
    /// Whose requests a revoke closes; none, it closes none.
    requests: Option<Arc<InMemoryApprovalRequests>>,
}

impl InMemoryKeyDirectory {
    pub fn keyed_by(history: Arc<InMemoryArchive>) -> Self {
        let state = Arc::default();
        *history.directory.lock().unwrap() = Some(Arc::clone(&state));
        Self {
            state,
            approvals: Arc::clone(&history.approvals),
            shares: Arc::clone(&history.shares),
            start_overs: Arc::clone(&history.start_overs),
            history: Some(history),
            requests: None,
        }
    }

    fn generation(&self, owner: UserId) -> Option<HistoryGeneration> {
        self.history
            .as_ref()
            .and_then(|history| history.state.lock().unwrap().generation(owner))
    }

    /// What [`DeviceTrust`] decides on, as held now.
    fn trust_of(&self, owner: UserId) -> DeviceTrust {
        let current = self.generation(owner);
        let state = self.state.lock().unwrap();
        DeviceTrust {
            devices: state
                .devices
                .iter()
                .filter(|device| device.owner == owner)
                .cloned()
                .collect(),
            approvals: self
                .approvals
                .lock()
                .unwrap()
                .iter()
                .filter(|(of, _)| *of == owner)
                .map(|(_, approval)| approval.clone())
                .collect(),
            current,
        }
    }

    pub fn relaying(self, requests: Arc<InMemoryApprovalRequests>) -> Self {
        Self {
            requests: Some(requests),
            ..self
        }
    }

    fn drop_approvals(&self, which: impl Fn(&Approval) -> bool) {
        self.approvals
            .lock()
            .unwrap()
            .retain(|(_, approval)| !which(approval));
    }

    fn drop_shares(&self, which: impl Fn(&KeyShare) -> bool) {
        self.shares
            .lock()
            .unwrap()
            .retain(|(_, share)| !which(share));
    }
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
                hpke_key: None,
                history_generation: None,
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
        read: Option<&Device>,
        attestation: &Attestation,
        hpke_key: &HpkeKeyWrite,
    ) -> Result<Attest, KeyStoreError> {
        let mut state = self.state.lock().unwrap();
        let current = state.devices.iter().find(|d| d.id == id);
        if current.is_some_and(|d| d.owner != owner) {
            return Err(KeyStoreError::DeviceTaken);
        }
        if current.is_some_and(Device::is_revoked) || keys(current) != keys(read) {
            return Ok(Attest::Stale);
        }
        let device = state.record(owner, id, label)?;
        let rotated = device
            .attestation
            .as_ref()
            .is_some_and(|held| held.root_key != attestation.root_key);
        let hpke_before = device.hpke_key.as_ref().map(|held| held.key.clone());
        device.attestation = Some(attestation.clone());
        match hpke_key {
            HpkeKeyWrite::Keep => {}
            HpkeKeyWrite::Set(signed) => device.hpke_key = Some(signed.into()),
            HpkeKeyWrite::Clear => device.hpke_key = None,
        }
        let resealed = hpke_before != device.hpke_key.as_ref().map(|held| held.key.clone());
        if rotated {
            self.drop_approvals(|approval| {
                approval.device == id || approval.approver == Approver::Device(id)
            });
            self.drop_shares(|share| share.sender == id);
        }
        if rotated || resealed {
            self.drop_shares(|share| share.recipient == id);
        }
        Ok(Attest::Stored)
    }

    async fn revoke(
        &self,
        owner: UserId,
        id: DeviceId,
        by: Option<DeviceId>,
        now: OffsetDateTime,
    ) -> Result<Revocation, KeyStoreError> {
        let trust = self.trust_of(owner);
        let Some(device) = trust.device(id) else {
            return Ok(Revocation::NotFound);
        };
        if device.is_revoked() {
            return Ok(Revocation::AlreadyRevoked);
        }
        if let Err(refusal) = may_revoke(id, by, &trust) {
            return Ok(Revocation::Refused(refusal));
        }
        let mut state = self.state.lock().unwrap();
        let device = state.device_mut(id).expect("read just now");
        device.revoked_at = Some(now);
        device.hpke_key = None;
        self.drop_approvals(|approval| approval.approver == Approver::Device(id));
        self.drop_shares(|share| share.sender == id || share.recipient == id);
        let closed = self
            .requests
            .as_ref()
            .map(|requests| requests.close_for(id, now))
            .unwrap_or_default();
        let start_over = end_open(&self.start_overs, now, |request| {
            (request.owner == owner && request.device == id).then_some(StartOverEnd::Revoked)
        })
        .pop();
        Ok(Revocation::Revoked { closed, start_over })
    }

    async fn hold_history_key(
        &self,
        owner: UserId,
        id: DeviceId,
        generation: HistoryGeneration,
    ) -> Result<Holding, KeyStoreError> {
        let current = self
            .history
            .as_ref()
            .and_then(|history| history.state.lock().unwrap().generation(owner));
        if check_history_generation(generation, current).is_err() {
            return Ok(Holding::Stale);
        }
        let mut state = self.state.lock().unwrap();
        match state
            .device_mut(id)
            .filter(|device| device.owner == owner && !device.is_revoked())
        {
            Some(device) => {
                device.history_generation = Some(generation);
                self.drop_shares(|share| share.recipient == id);
                Ok(Holding::Recorded)
            }
            None => Ok(Holding::Refused),
        }
    }
}

/// `at` as Postgres keeps it, to the microsecond: what a store hands back is what it holds.
pub(super) fn stored(at: OffsetDateTime) -> OffsetDateTime {
    at.replace_nanosecond(at.nanosecond() / 1000 * 1000)
        .expect("fewer nanoseconds stay valid")
}

/// Ends the open requests `how` names an end for, as they ended.
fn end_open(
    start_overs: &StartOvers,
    at: OffsetDateTime,
    how: impl Fn(&StartOverRequest) -> Option<StartOverEnd>,
) -> Vec<StartOverRequest> {
    let at = stored(at);
    let mut ended = Vec::new();
    for request in start_overs.lock().unwrap().iter_mut() {
        if let Some(how) = how(request).filter(|_| request.is_open()) {
            request.ended = Some(StartOverEnding { how, at });
            ended.push(request.clone());
        }
    }
    ended
}

/// What a registration's write is guarded on, besides the device being unrevoked.
fn keys(device: Option<&Device>) -> (Option<&DeviceRootKey>, Option<&HpkePublicKey>) {
    (
        device
            .and_then(|d| d.attestation.as_ref())
            .map(|a| &a.root_key),
        device
            .and_then(|d| d.hpke_key.as_ref())
            .map(|held| &held.key),
    )
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
        relabel: bool,
        packages: &[NewKeyPackage],
    ) -> Result<usize, KeyStoreError> {
        let mut state = self.state.lock().unwrap();
        let recorded = state.record(owner, device, label)?;
        recorded.last_seen_at = OffsetDateTime::now_utc();
        if relabel {
            recorded.label = label.clone();
        }
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
        expires_at: AttestationExpiry,
    ) -> SignedAttestation {
        let signed_message = format!(
            "{actor}\n{device}\n{:?}\n{}",
            key.as_bytes(),
            expires_at.at()
        )
        .into_bytes();
        SignedAttestation {
            signature: signed_message.iter().rev().copied().collect(),
            kid: "test-key".to_owned(),
            signed_message,
        }
    }
}

/// Takes for a signature what [`plain_signature`] makes: no cryptography.
pub struct PlainEd25519Verifier;

impl Ed25519Verifier for PlainEd25519Verifier {
    fn verifies(
        &self,
        key: &dyn Ed25519PublicKey,
        message: &[u8],
        signature: &Ed25519Signature,
    ) -> bool {
        plain_signature(key, message) == *signature
    }
}

/// `key`'s "signature" over `message` as [`PlainEd25519Verifier`] takes it: two SHA-256 rounds.
pub fn plain_signature(key: &dyn Ed25519PublicKey, message: &[u8]) -> Ed25519Signature {
    use sha2::{Digest, Sha256};
    let first = Sha256::new()
        .chain_update(key.public_bytes())
        .chain_update(message)
        .finalize();
    let second = Sha256::digest(first);
    Ed25519Signature::parse("signature", &[first.as_slice(), second.as_slice()].concat())
        .expect("two digests are 64 bytes")
}

/// The HPKE key `[byte; 32]`, verified as root key `[byte; 32]` signed it for a test device.
pub fn hpke_key(byte: u8) -> SignedHpkeKey {
    let root = DeviceRootKey::parse(&[byte; 32]).unwrap();
    let actor = ActorUri::parse("https://idp.test/users/alice_t3st0").unwrap();
    let device = DeviceId::from(uuid::Uuid::nil());
    let key = HpkePublicKey::parse(&[byte; 32]).unwrap();
    let signature = plain_signature(&root, &key.canonical_bytes(&actor, device));
    UnverifiedHpkeKey::new(key, signature)
        .verified(&root, &actor, device, &PlainEd25519Verifier)
        .expect("signed by its root key")
}

/// [`hpke_key`] as the directory reads it back.
pub fn held(byte: u8) -> HeldHpkeKey {
    HeldHpkeKey::from(&hpke_key(byte))
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

/// Each account's archive entries and history key, over one state: a new key erases the archive,
/// and an upload is kept only under the current one. A new key also drops the approvals of older
/// generations and the key shares, and ends the start over requests, which a directory
/// [`InMemoryKeyDirectory::keyed_by`] this one shares.
#[derive(Default)]
pub struct InMemoryArchive {
    state: Mutex<ArchiveState>,
    approvals: Approvals,
    shares: Shares,
    start_overs: StartOvers,
    /// The devices of the directory keyed by this one; none, no device is approved.
    directory: Mutex<Option<Arc<Mutex<State>>>>,
    /// Whose sessions' last uses a start over waits on; none, no device was ever used.
    sessions: Option<Arc<InMemorySessions>>,
}

impl InMemoryArchive {
    /// One that reads the approved devices' last uses from `sessions`.
    pub fn watching(sessions: Arc<InMemorySessions>) -> Self {
        Self {
            sessions: Some(sessions),
            ..Self::default()
        }
    }

    fn devices_of(&self, owner: UserId) -> Vec<Device> {
        self.directory
            .lock()
            .unwrap()
            .as_ref()
            .map(|state| {
                state
                    .lock()
                    .unwrap()
                    .devices
                    .iter()
                    .filter(|device| device.owner == owner)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[derive(Default)]
struct ArchiveState {
    entries: Vec<(UserId, ArchiveEntry)>,
    keys: Vec<HeldKey>,
}

struct HeldKey {
    owner: UserId,
    key: HistoryKey,
    set_by: DeviceId,
}

impl ArchiveState {
    fn generation(&self, owner: UserId) -> Option<HistoryGeneration> {
        self.keys
            .iter()
            .find(|held| held.owner == owner)
            .map(|held| held.key.generation)
    }
}

#[async_trait::async_trait]
impl HistoryArchive for InMemoryArchive {
    async fn store(
        &self,
        owner: UserId,
        generation: HistoryGeneration,
        entries: &[NewArchiveEntry],
    ) -> Result<Archived, ArchiveStoreError> {
        // One upload, one moment: its entries share their `created_at`.
        let now = OffsetDateTime::now_utc();
        let mut state = self.state.lock().unwrap();
        if check_history_generation(generation, state.generation(owner)).is_err() {
            return Ok(Archived::Stale);
        }
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
        Ok(Archived::Stored(stored))
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
}

#[async_trait::async_trait]
impl HistoryKeys for InMemoryArchive {
    async fn current(&self, owner: UserId) -> Result<Option<HeldHistoryKey>, ArchiveStoreError> {
        let state = self.state.lock().unwrap();
        Ok(state
            .keys
            .iter()
            .find(|held| held.owner == owner)
            .map(|held| HeldHistoryKey {
                key: held.key.clone(),
                set_by: Some(held.set_by),
            }))
    }

    async fn replace(
        &self,
        owner: UserId,
        key: &HistoryKey,
        set_by: DeviceId,
        now: OffsetDateTime,
    ) -> Result<KeyReplace, ArchiveStoreError> {
        let sessions = match &self.sessions {
            Some(sessions) => sessions
                .of_user(owner)
                .await
                .map_err(|e| ArchiveStoreError::Unexpected(e.into()))?,
            None => Vec::new(),
        };
        let devices = self.devices_of(owner);
        let mut state = self.state.lock().unwrap();
        let held = state
            .keys
            .iter()
            .find(|held| held.owner == owner)
            .map(|held| held.key.clone());
        let trust = DeviceTrust {
            devices,
            approvals: self
                .approvals
                .lock()
                .unwrap()
                .iter()
                .filter(|(of, _)| *of == owner)
                .map(|(_, approval)| approval.clone())
                .collect(),
            current: held.as_ref().map(|held| held.generation),
        };
        let open = self
            .start_overs
            .lock()
            .unwrap()
            .iter()
            .find(|request| request.owner == owner && request.is_open())
            .cloned();
        let gate = may_replace_history_key(
            key,
            set_by,
            held.as_ref(),
            &trust,
            open.as_ref(),
            &sessions,
            now,
        );
        let used = match gate {
            Ok(KeyGate::AlreadySet) => return Ok(KeyReplace::AlreadySet),
            Ok(KeyGate::Write(matured)) => matured.map(|matured| matured.request()),
            Err(ArchiveError::KeyConflict { current }) => return Ok(KeyReplace::Conflict(current)),
            Err(ArchiveError::StartOver(refusal)) => return Ok(KeyReplace::Refused(refusal)),
            Err(other) => return Err(ArchiveStoreError::Unexpected(other.into())),
        };
        state.keys.retain(|held| held.owner != owner);
        state.keys.push(HeldKey {
            owner,
            key: key.clone(),
            set_by,
        });
        self.approvals.lock().unwrap().retain(|(of, approval)| {
            *of != owner
                || !matches!(approval.approver, Approver::Passphrase(older) if older < key.generation)
        });
        self.shares.lock().unwrap().retain(|(of, _)| *of != owner);
        let closed = end_open(&self.start_overs, now, |request| {
            (request.owner == owner).then_some(if Some(request.id) == used {
                StartOverEnd::Used
            } else {
                StartOverEnd::Superseded
            })
        })
        .into_iter()
        .filter(|request| Some(request.id) != used)
        .collect();
        let before = state.entries.len();
        state.entries.retain(|(o, _)| *o != owner);
        Ok(KeyReplace::Replaced {
            erased: before - state.entries.len(),
            closed,
        })
    }
}

/// What every store of devices and KeyPackages must do. Timestamps are whole seconds, which
/// every store keeps exactly.
pub mod contract {
    use time::Duration;

    pub use super::approval::contract::*;
    pub use super::key_share::contract::*;
    pub use super::start_over::contract::*;

    use super::*;
    use crate::e2ee::{DeviceApprovals, DeviceKind, KeyPackageBytes};

    pub(super) fn at(offset: Duration) -> OffsetDateTime {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        OffsetDateTime::from_unix_timestamp(now).unwrap() + offset
    }

    pub(super) fn label(name: &str) -> DeviceLabel {
        DeviceLabel {
            name: name.to_owned(),
            kind: DeviceKind::Laptop,
        }
    }

    pub(super) fn attestation(key: u8) -> Attestation {
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

    fn set(byte: u8) -> HpkeKeyWrite {
        HpkeKeyWrite::Set(hpke_key(byte))
    }

    /// A registration that read the device just before writing.
    pub(super) async fn register(
        devices: &dyn Devices,
        owner: UserId,
        id: DeviceId,
        attestation: &Attestation,
        hpke_key: HpkeKeyWrite,
    ) -> Attest {
        let read = devices.find(id).await.unwrap();
        devices
            .attest(
                owner,
                id,
                &label("laptop"),
                read.as_ref(),
                attestation,
                &hpke_key,
            )
            .await
            .unwrap()
    }

    pub async fn a_registered_device_is_found_and_listed_with_its_attestation(
        devices: &dyn Devices,
        alice: UserId,
    ) {
        let (id, attested) = (DeviceId::generate(), attestation(1));

        let stored = devices
            .attest(
                alice,
                id,
                &label("Firefox on Linux"),
                None,
                &attested,
                &HpkeKeyWrite::Clear,
            )
            .await
            .unwrap();

        let device = devices.find(id).await.unwrap().expect("recorded");
        assert_eq!(
            (device.owner, &device.label, device.revoked_at),
            (alice, &label("Firefox on Linux"), None)
        );
        assert_eq!(stored, Attest::Stored);
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
            .attest(
                alice,
                id,
                &label("first"),
                None,
                &attestation(1),
                &HpkeKeyWrite::Clear,
            )
            .await
            .unwrap();
        let read = devices.find(id).await.unwrap();

        let renewed = attestation(2);
        devices
            .attest(
                alice,
                id,
                &label("second"),
                read.as_ref(),
                &renewed,
                &HpkeKeyWrite::Clear,
            )
            .await
            .unwrap();

        let device = devices.find(id).await.unwrap().unwrap();
        assert_eq!(
            (device.label, device.attestation),
            (label("first"), Some(renewed))
        );
    }

    pub async fn a_device_holds_the_hpke_key_registered_with_its_attestation_until_replaced(
        devices: &dyn Devices,
        alice: UserId,
    ) {
        let id = DeviceId::generate();

        register(devices, alice, id, &attestation(1), set(1)).await;
        let registered = devices.find(id).await.unwrap().unwrap().hpke_key;
        let listed = devices.list(alice).await.unwrap()[0].hpke_key.clone();
        register(devices, alice, id, &attestation(1), HpkeKeyWrite::Keep).await;
        let kept = devices.find(id).await.unwrap().unwrap().hpke_key;
        register(devices, alice, id, &attestation(1), set(2)).await;
        let replaced = devices.find(id).await.unwrap().unwrap().hpke_key;
        register(devices, alice, id, &attestation(2), HpkeKeyWrite::Clear).await;
        let cleared = devices.find(id).await.unwrap().unwrap().hpke_key;

        assert_eq!(registered, Some(held(1)));
        assert_eq!(listed, Some(held(1)));
        assert_eq!(kept, Some(held(1)));
        assert_eq!(replaced, Some(held(2)));
        assert_eq!(cleared, None);
    }

    pub async fn a_registration_decided_on_a_stale_read_writes_nothing(
        devices: &dyn Devices,
        alice: UserId,
    ) {
        let id = DeviceId::generate();
        register(devices, alice, id, &attestation(1), set(1)).await;
        let read_before_the_new_key = devices.find(id).await.unwrap();
        register(devices, alice, id, &attestation(1), set(2)).await;
        let keyed = devices.find(id).await.unwrap();
        let attest = |read: Option<Device>| async move {
            devices
                .attest(
                    alice,
                    id,
                    &label("laptop"),
                    read.as_ref(),
                    &attestation(3),
                    &HpkeKeyWrite::Keep,
                )
                .await
                .unwrap()
        };

        let as_if_unknown = attest(None).await;
        let before_the_new_key = attest(read_before_the_new_key).await;
        let unchanged = devices.find(id).await.unwrap();
        devices
            .revoke(alice, id, Some(id), time::OffsetDateTime::now_utc())
            .await
            .unwrap();
        let revoked = devices.find(id).await.unwrap();
        let after_the_revoke = attest(keyed.clone()).await;

        assert_eq!(
            (as_if_unknown, before_the_new_key, after_the_revoke),
            (Attest::Stale, Attest::Stale, Attest::Stale)
        );
        assert_eq!(unchanged, keyed);
        assert_eq!(devices.find(id).await.unwrap(), revoked);
    }

    pub async fn a_revoked_device_holds_no_hpke_key(devices: &dyn Devices, alice: UserId) {
        let (id, attested) = (DeviceId::generate(), attestation(1));
        register(devices, alice, id, &attested, set(1)).await;

        devices
            .revoke(alice, id, Some(id), time::OffsetDateTime::now_utc())
            .await
            .unwrap();

        let revoked = devices.find(id).await.unwrap().unwrap();
        assert_eq!(revoked.hpke_key, None);
        assert_eq!(revoked.attestation, Some(attested));
    }

    /// `keys` is the store whose current generation `devices` checks a report against.
    pub async fn a_device_records_the_current_history_generation_while_unrevoked(
        devices: &dyn Devices,
        approvals: &dyn DeviceApprovals,
        keys: &dyn HistoryKeys,
        alice: UserId,
        bob: UserId,
    ) {
        let (laptop, phone, bobs) = (
            DeviceId::generate(),
            DeviceId::generate(),
            DeviceId::generate(),
        );
        for (owner, id) in [(alice, laptop), (alice, phone), (bob, bobs)] {
            register(devices, owner, id, &attestation(1), HpkeKeyWrite::Clear).await;
        }
        let (first, second) = (
            HistoryGeneration::FIRST,
            HistoryGeneration::parse(2).unwrap(),
        );

        let before_any = devices
            .hold_history_key(alice, laptop, first)
            .await
            .unwrap();
        keys.replace(
            alice,
            &history_key(1, 1),
            laptop,
            time::OffsetDateTime::now_utc(),
        )
        .await
        .unwrap();
        let recorded = devices
            .hold_history_key(alice, laptop, first)
            .await
            .unwrap();
        let ahead = devices
            .hold_history_key(alice, phone, second)
            .await
            .unwrap();
        let anothers = devices.hold_history_key(alice, bobs, first).await.unwrap();
        let unknown = devices
            .hold_history_key(alice, DeviceId::generate(), first)
            .await
            .unwrap();
        devices
            .revoke(alice, phone, Some(phone), time::OffsetDateTime::now_utc())
            .await
            .unwrap();
        let revoked = devices.hold_history_key(alice, phone, first).await.unwrap();
        approve_by_its_words(devices, approvals, alice, laptop, &history_key(1, 1)).await;
        keys.replace(
            alice,
            &history_key(2, 2),
            laptop,
            time::OffsetDateTime::now_utc(),
        )
        .await
        .unwrap();
        let replaced = devices
            .hold_history_key(alice, laptop, first)
            .await
            .unwrap();

        for stale in [before_any, ahead, replaced] {
            assert_eq!(stale, Holding::Stale);
        }
        assert_eq!(recorded, Holding::Recorded);
        for refused in [anothers, unknown, revoked] {
            assert_eq!(refused, Holding::Refused);
        }
        let listed: Vec<_> = devices
            .list(alice)
            .await
            .unwrap()
            .into_iter()
            .map(|d| (d.id, d.history_generation))
            .collect();
        assert_eq!(listed, vec![(laptop, Some(first)), (phone, None)]);
        assert_eq!(
            devices
                .find(bobs)
                .await
                .unwrap()
                .unwrap()
                .history_generation,
            None
        );
    }

    pub async fn stashing_keeps_the_hpke_key_registered(
        devices: &dyn Devices,
        packages: &dyn KeyPackages,
        alice: UserId,
    ) {
        let id = DeviceId::generate();
        register(devices, alice, id, &attestation(1), set(1)).await;

        packages
            .stash(alice, id, &label("laptop"), false, &[fresh(1)])
            .await
            .unwrap();

        let device = devices.find(id).await.unwrap().unwrap();
        assert_eq!(device.hpke_key, Some(held(1)));
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
            register(devices, alice, id, &attestation(1), HpkeKeyWrite::Clear).await;
        }
        register(
            devices,
            bob,
            DeviceId::generate(),
            &attestation(1),
            HpkeKeyWrite::Clear,
        )
        .await;
        devices
            .revoke(alice, recent, Some(recent), time::OffsetDateTime::now_utc())
            .await
            .unwrap();
        packages
            .stash(alice, seen, &label("laptop"), false, &[fresh(1)])
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
        register(devices, alice, id, &attestation(1), HpkeKeyWrite::Clear).await;

        assert_eq!(
            devices
                .revoke(bob, id, Some(id), time::OffsetDateTime::now_utc())
                .await
                .unwrap(),
            Revocation::NotFound
        );
        assert_eq!(
            devices
                .revoke(alice, id, Some(id), time::OffsetDateTime::now_utc())
                .await
                .unwrap(),
            Revocation::Revoked {
                closed: vec![],
                start_over: None
            }
        );
        assert_eq!(
            devices
                .revoke(alice, id, Some(id), time::OffsetDateTime::now_utc())
                .await
                .unwrap(),
            Revocation::AlreadyRevoked
        );
        assert_eq!(
            devices
                .revoke(
                    alice,
                    DeviceId::generate(),
                    Some(DeviceId::generate()),
                    time::OffsetDateTime::now_utc()
                )
                .await
                .unwrap(),
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
                false,
                &[fresh(1), fresh(2), fresh(3)],
            )
            .await
            .unwrap();
        let stored = packages
            .stash(
                alice,
                phone,
                &label("phone"),
                false,
                &[fresh(4), package(5, -Duration::minutes(1))],
            )
            .await
            .unwrap();
        packages
            .stash(
                bob,
                DeviceId::generate(),
                &label("bob's"),
                false,
                &[fresh(6)],
            )
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
            .stash(alice, id, &label("Chrome on Android"), false, &[fresh(1)])
            .await
            .unwrap();
        let recorded = devices.find(id).await.unwrap().expect("recorded");

        packages
            .stash(alice, id, &label("another name"), false, &[fresh(2)])
            .await
            .unwrap();

        let seen = devices.find(id).await.unwrap().unwrap();
        assert_eq!(
            (
                recorded.owner,
                &recorded.label,
                &recorded.attestation,
                &recorded.hpke_key
            ),
            (alice, &label("Chrome on Android"), &None, &None)
        );
        assert_eq!(seen.label, label("Chrome on Android"));
        assert!(seen.last_seen_at >= recorded.last_seen_at);
    }

    /// A device registered before its client said what it is, then named by a stash asked to.
    pub async fn a_known_device_takes_a_stashs_label_only_when_asked(
        devices: &dyn Devices,
        packages: &dyn KeyPackages,
        alice: UserId,
    ) {
        let id = DeviceId::generate();
        devices
            .attest(
                alice,
                id,
                &DeviceLabel::unknown(),
                None,
                &attestation(1),
                &HpkeKeyWrite::Clear,
            )
            .await
            .unwrap();

        packages
            .stash(alice, id, &label("Chrome on Linux"), false, &[fresh(1)])
            .await
            .unwrap();
        let still_unknown = devices.find(id).await.unwrap().unwrap().label;
        packages
            .stash(alice, id, &label("Chrome on Linux"), true, &[fresh(2)])
            .await
            .unwrap();
        let named = devices.find(id).await.unwrap().unwrap().label;
        packages
            .stash(alice, id, &label("Firefox on Linux"), false, &[fresh(3)])
            .await
            .unwrap();

        assert_eq!(still_unknown, DeviceLabel::unknown());
        assert_eq!(named, label("Chrome on Linux"));
        assert_eq!(
            devices.find(id).await.unwrap().unwrap().label,
            label("Chrome on Linux")
        );
    }

    pub async fn a_claim_hands_out_the_oldest_package_once(
        packages: &dyn KeyPackages,
        alice: UserId,
    ) {
        let (device, oldest) = (DeviceId::generate(), fresh(1));
        for stashed in [oldest.clone(), fresh(2)] {
            packages
                .stash(alice, device, &label("laptop"), false, &[stashed])
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
                false,
                &[package(1, -Duration::minutes(1))],
            )
            .await
            .unwrap();
        packages
            .stash(alice, stocked, &label("phone"), false, &[fresh(2)])
            .await
            .unwrap();
        packages
            .stash(
                bob,
                DeviceId::generate(),
                &label("bob's"),
                false,
                &[fresh(3)],
            )
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
            .stash(alice, revoked, &label("stolen phone"), false, &[fresh(1)])
            .await
            .unwrap();
        packages
            .stash(alice, laptop, &label("laptop"), false, &[fresh(2)])
            .await
            .unwrap();
        devices
            .revoke(
                alice,
                revoked,
                Some(revoked),
                time::OffsetDateTime::now_utc(),
            )
            .await
            .unwrap();

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
        register(devices, alice, id, &attestation(1), HpkeKeyWrite::Clear).await;
        let before = devices.find(id).await.unwrap();

        let attested = devices
            .attest(bob, id, &label("bob's"), None, &attestation(2), &set(2))
            .await;
        let stashed = packages
            .stash(bob, id, &label("bob's"), false, &[fresh(1)])
            .await;

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
                false,
                &[package(1, -Duration::minutes(1)), fresh(2)],
            )
            .await
            .unwrap();
        packages
            .stash(alice, device, &label("laptop"), false, &[fresh(3)])
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

    /// Generation `generation`, its salt, check value and approval key made of `byte`s.
    pub(super) fn history_key(generation: i64, byte: u8) -> HistoryKey {
        HistoryKey {
            generation: HistoryGeneration::parse(generation).unwrap(),
            salt: crate::e2ee::HistorySalt::parse(&[byte; 16]).unwrap(),
            check_value: crate::e2ee::HistoryCheckValue::parse(&[byte; 32]).unwrap(),
            approval_public_key: crate::e2ee::ApprovalPublicKey::parse(&[byte.wrapping_add(1); 32])
                .unwrap(),
        }
    }

    /// A device of `owner`'s, which a history key may name as having set it.
    async fn a_device(devices: &dyn Devices, owner: UserId) -> DeviceId {
        let id = DeviceId::generate();
        register(devices, owner, id, &attestation(1), HpkeKeyWrite::Clear).await;
        id
    }

    /// `device` approved by `key`'s words, so it may set the generation after `key`'s.
    async fn approve_by_its_words(
        devices: &dyn Devices,
        approvals: &dyn DeviceApprovals,
        owner: UserId,
        device: DeviceId,
        key: &HistoryKey,
    ) {
        let approval = super::approval::contract::by_passphrase(devices, device, key).await;
        approvals.approve(owner, &approval).await.unwrap();
    }

    /// The owner's first history key, set by a device of theirs.
    async fn first_key(
        keys: &dyn HistoryKeys,
        devices: &dyn Devices,
        owner: UserId,
    ) -> HistoryGeneration {
        let device = a_device(devices, owner).await;
        let replaced = keys
            .replace(
                owner,
                &history_key(1, 1),
                device,
                time::OffsetDateTime::now_utc(),
            )
            .await
            .unwrap();
        assert_eq!(
            replaced,
            KeyReplace::Replaced {
                erased: 0,
                closed: vec![]
            }
        );
        HistoryGeneration::FIRST
    }

    async fn archive_under(
        archive: &dyn HistoryArchive,
        owner: UserId,
        generation: HistoryGeneration,
        entries: &[NewArchiveEntry],
    ) -> usize {
        match archive.store(owner, generation, entries).await.unwrap() {
            Archived::Stored(new) => new,
            Archived::Stale => panic!("{generation:?} is not the current key"),
        }
    }

    /// `conversation` is one the store may reference.
    pub async fn an_entry_is_archived_once_per_owner(
        archive: &dyn HistoryArchive,
        keys: &dyn HistoryKeys,
        devices: &dyn Devices,
        alice: UserId,
        bob: UserId,
        conversation: ConversationId,
    ) {
        let alices = first_key(keys, devices, alice).await;
        let bobs = first_key(keys, devices, bob).await;
        let entries = [archived(conversation, 1), archived(conversation, 2)];

        let first = archive_under(archive, alice, alices, &entries).await;
        let again = archive_under(archive, alice, alices, &entries).await;
        let bobs = archive_under(archive, bob, bobs, &entries[..1]).await;

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
        keys: &dyn HistoryKeys,
        devices: &dyn Devices,
        alice: UserId,
        conversation: ConversationId,
    ) {
        let generation = first_key(keys, devices, alice).await;
        let older: Vec<NewArchiveEntry> = (1..=3).map(|b| archived(conversation, b)).collect();
        let newer: Vec<NewArchiveEntry> = (4..=5).map(|b| archived(conversation, b)).collect();
        archive_under(archive, alice, generation, &older).await;
        archive_under(archive, alice, generation, &newer).await;

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

    pub async fn clearing_an_archive_deletes_its_owners_entries_and_keeps_the_key(
        archive: &dyn HistoryArchive,
        keys: &dyn HistoryKeys,
        devices: &dyn Devices,
        alice: UserId,
        bob: UserId,
        conversation: ConversationId,
    ) {
        let alices = first_key(keys, devices, alice).await;
        let bobs = first_key(keys, devices, bob).await;
        archive_under(
            archive,
            alice,
            alices,
            &[archived(conversation, 1), archived(conversation, 2)],
        )
        .await;
        archive_under(archive, bob, bobs, &[archived(conversation, 3)]).await;

        let cleared = archive.clear(alice).await.unwrap();

        assert_eq!(cleared, 2);
        assert!(archive.page(alice, None, 10).await.unwrap().is_empty());
        assert_eq!(archive.page(bob, None, 10).await.unwrap().len(), 1);
        assert_eq!(
            keys.current(alice).await.unwrap().map(|held| held.key),
            Some(history_key(1, 1)),
            "the key stays"
        );
        assert_eq!(
            archive_under(archive, alice, alices, &[archived(conversation, 4)]).await,
            1,
            "and is saved under still"
        );
    }

    pub async fn an_upload_is_stored_only_under_the_current_generation(
        archive: &dyn HistoryArchive,
        keys: &dyn HistoryKeys,
        devices: &dyn Devices,
        approvals: &dyn DeviceApprovals,
        alice: UserId,
        conversation: ConversationId,
    ) {
        let (first, second) = (
            HistoryGeneration::FIRST,
            HistoryGeneration::parse(2).unwrap(),
        );
        let entries = [archived(conversation, 1)];

        let before_any = archive.store(alice, first, &entries).await.unwrap();
        first_key(keys, devices, alice).await;
        let ahead = archive.store(alice, second, &entries).await.unwrap();
        let device = a_device(devices, alice).await;
        approve_by_its_words(devices, approvals, alice, device, &history_key(1, 1)).await;
        keys.replace(
            alice,
            &history_key(2, 2),
            device,
            time::OffsetDateTime::now_utc(),
        )
        .await
        .unwrap();
        let replaced = archive.store(alice, first, &entries).await.unwrap();
        let current = archive.store(alice, second, &entries).await.unwrap();

        for refused in [before_any, ahead, replaced] {
            assert_eq!(refused, Archived::Stale);
        }
        assert_eq!(current, Archived::Stored(1));
        assert_eq!(archive.page(alice, None, 10).await.unwrap().len(), 1);
    }

    pub async fn a_key_is_set_only_for_the_generation_after_the_current_one(
        keys: &dyn HistoryKeys,
        devices: &dyn Devices,
        approvals: &dyn DeviceApprovals,
        alice: UserId,
        bob: UserId,
    ) {
        let generation = |raw| Some(HistoryGeneration::parse(raw).unwrap());
        let (laptop, phone) = (
            a_device(devices, alice).await,
            a_device(devices, alice).await,
        );

        let unset = keys.current(alice).await.unwrap();
        let skipping = keys
            .replace(
                alice,
                &history_key(2, 2),
                laptop,
                time::OffsetDateTime::now_utc(),
            )
            .await
            .unwrap();
        let first = keys
            .replace(
                alice,
                &history_key(1, 1),
                laptop,
                time::OffsetDateTime::now_utc(),
            )
            .await
            .unwrap();
        let raced = keys
            .replace(
                alice,
                &history_key(1, 9),
                phone,
                time::OffsetDateTime::now_utc(),
            )
            .await
            .unwrap();
        let ahead = keys
            .replace(
                alice,
                &history_key(3, 3),
                phone,
                time::OffsetDateTime::now_utc(),
            )
            .await
            .unwrap();
        let held_first = keys.current(alice).await.unwrap();
        approve_by_its_words(devices, approvals, alice, phone, &history_key(1, 1)).await;
        let second = keys
            .replace(
                alice,
                &history_key(2, 2),
                phone,
                time::OffsetDateTime::now_utc(),
            )
            .await
            .unwrap();
        let back = keys
            .replace(
                alice,
                &history_key(1, 1),
                laptop,
                time::OffsetDateTime::now_utc(),
            )
            .await
            .unwrap();

        assert_eq!(unset, None);
        assert_eq!(skipping, KeyReplace::Conflict(None));
        assert_eq!(
            first,
            KeyReplace::Replaced {
                erased: 0,
                closed: vec![]
            }
        );
        assert_eq!(raced, KeyReplace::Conflict(generation(1)));
        assert_eq!(ahead, KeyReplace::Conflict(generation(1)));
        assert_eq!(
            held_first,
            Some(HeldHistoryKey {
                key: history_key(1, 1),
                set_by: Some(laptop),
            }),
            "the first one's, by the device that set it"
        );
        assert_eq!(
            second,
            KeyReplace::Replaced {
                erased: 0,
                closed: vec![]
            }
        );
        assert_eq!(back, KeyReplace::Conflict(generation(2)));
        assert_eq!(
            keys.current(alice).await.unwrap(),
            Some(HeldHistoryKey {
                key: history_key(2, 2),
                set_by: Some(phone),
            })
        );
        assert_eq!(keys.current(bob).await.unwrap(), None);
    }

    pub async fn setting_the_key_held_again_is_a_retry_that_writes_nothing(
        archive: &dyn HistoryArchive,
        keys: &dyn HistoryKeys,
        devices: &dyn Devices,
        approvals: &dyn DeviceApprovals,
        alice: UserId,
        conversation: ConversationId,
    ) {
        let (laptop, phone) = (
            a_device(devices, alice).await,
            a_device(devices, alice).await,
        );
        keys.replace(
            alice,
            &history_key(1, 1),
            laptop,
            time::OffsetDateTime::now_utc(),
        )
        .await
        .unwrap();
        approve_by_its_words(devices, approvals, alice, laptop, &history_key(1, 1)).await;
        keys.replace(
            alice,
            &history_key(2, 2),
            laptop,
            time::OffsetDateTime::now_utc(),
        )
        .await
        .unwrap();
        archive_under(
            archive,
            alice,
            HistoryGeneration::parse(2).unwrap(),
            &[archived(conversation, 1)],
        )
        .await;

        let again = keys
            .replace(
                alice,
                &history_key(2, 2),
                phone,
                time::OffsetDateTime::now_utc(),
            )
            .await
            .unwrap();
        let older = keys
            .replace(
                alice,
                &history_key(1, 1),
                laptop,
                time::OffsetDateTime::now_utc(),
            )
            .await
            .unwrap();

        assert_eq!(again, KeyReplace::AlreadySet);
        assert_eq!(
            older,
            KeyReplace::Conflict(Some(HistoryGeneration::parse(2).unwrap())),
            "only the key held"
        );
        assert_eq!(archive.page(alice, None, 10).await.unwrap().len(), 1);
        assert_eq!(
            keys.current(alice)
                .await
                .unwrap()
                .and_then(|held| held.set_by),
            Some(laptop),
            "still the device that set it"
        );
    }

    pub async fn a_new_generation_erases_its_owners_archive_in_the_same_write(
        archive: &dyn HistoryArchive,
        keys: &dyn HistoryKeys,
        devices: &dyn Devices,
        approvals: &dyn DeviceApprovals,
        alice: UserId,
        bob: UserId,
        conversation: ConversationId,
    ) {
        let alices = first_key(keys, devices, alice).await;
        let bobs = first_key(keys, devices, bob).await;
        let device = a_device(devices, alice).await;
        approve_by_its_words(devices, approvals, alice, device, &history_key(1, 1)).await;
        archive_under(
            archive,
            alice,
            alices,
            &[archived(conversation, 1), archived(conversation, 2)],
        )
        .await;
        archive_under(archive, bob, bobs, &[archived(conversation, 3)]).await;

        let refused = keys
            .replace(
                alice,
                &history_key(3, 3),
                device,
                time::OffsetDateTime::now_utc(),
            )
            .await
            .unwrap();
        let kept = archive.page(alice, None, 10).await.unwrap().len();
        let replaced = keys
            .replace(
                alice,
                &history_key(2, 2),
                device,
                time::OffsetDateTime::now_utc(),
            )
            .await
            .unwrap();

        assert_eq!(refused, KeyReplace::Conflict(Some(alices)));
        assert_eq!(kept, 2, "a conflict erases nothing");
        assert_eq!(
            replaced,
            KeyReplace::Replaced {
                erased: 2,
                closed: vec![]
            }
        );
        assert!(archive.page(alice, None, 10).await.unwrap().is_empty());
        assert_eq!(archive.page(bob, None, 10).await.unwrap().len(), 1);
    }
}

#[cfg(test)]
mod tests;
