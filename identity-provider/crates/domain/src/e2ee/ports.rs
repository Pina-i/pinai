use time::OffsetDateTime;

use crate::identity::{ActorUri, RemoteActor};
use crate::messaging::GroupSnapshot;
use crate::{ConversationId, DeviceId, UserId};

use super::{
    Append, ArchiveCursor, ArchiveEntry, ArchiveSalt, ArchiveStoreError, Attestation, Claim,
    ClaimedKeyPackage, Commit, DeliveryStoreError, Device, DeviceLabel, DeviceRootKey, Epoch,
    KeyStoreError, NewArchiveEntry, NewCommit, NewKeyPackage, NewWelcome, RemoteClaimError,
    Welcome, WelcomeBlob,
};

/// The devices accounts registered, and their attestations.
#[async_trait::async_trait]
pub trait Devices: Send + Sync {
    async fn find(&self, id: DeviceId) -> Result<Option<Device>, KeyStoreError>;
    /// The owner's devices: active ones first, each group most recently seen first.
    async fn list(&self, owner: UserId) -> Result<Vec<Device>, KeyStoreError>;
    /// Store the device's attestation, recording the device under `label` if it is new.
    async fn attest(
        &self,
        owner: UserId,
        id: DeviceId,
        label: &DeviceLabel,
        attestation: &Attestation,
    ) -> Result<(), KeyStoreError>;
    async fn revoke(&self, owner: UserId, id: DeviceId) -> Result<Revocation, KeyStoreError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Revocation {
    Revoked,
    AlreadyRevoked,
    /// No such device of the owner's.
    NotFound,
}

/// The KeyPackages devices publish ahead of time, each handed out once.
#[async_trait::async_trait]
pub trait KeyPackages: Send + Sync {
    /// Unclaimed, unexpired KeyPackages of one device.
    async fn available(&self, owner: UserId, device: DeviceId) -> Result<usize, KeyStoreError>;
    /// The same count for every device of the owner's that has any.
    async fn available_per_device(
        &self,
        owner: UserId,
    ) -> Result<Vec<(DeviceId, usize)>, KeyStoreError>;
    /// Store a batch and mark the device seen, recording it under `label` if it is new. How
    /// many were stored.
    async fn stash(
        &self,
        owner: UserId,
        device: DeviceId,
        label: &DeviceLabel,
        packages: &[NewKeyPackage],
    ) -> Result<usize, KeyStoreError>;
    /// The oldest available KeyPackage of `device`, or of any of the owner's devices; never
    /// handed out twice.
    async fn claim(
        &self,
        owner: UserId,
        device: Option<DeviceId>,
    ) -> Result<Option<ClaimedKeyPackage>, KeyStoreError>;
    /// Delete what expired before `expired_before` and what was claimed before
    /// `claimed_before`. How many were deleted.
    async fn delete_spent(
        &self,
        expired_before: OffsetDateTime,
        claimed_before: OffsetDateTime,
    ) -> Result<usize, KeyStoreError>;
}

/// The IdP's signature over a device attestation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedAttestation {
    pub signature: Vec<u8>,
    pub kid: String,
    /// The exact bytes signed, so the client can verify before trusting them.
    pub signed_message: Vec<u8>,
}

/// Signs device attestations with the instance's key.
pub trait DeviceAttester: Send + Sync {
    fn attest(
        &self,
        actor: &ActorUri,
        device: DeviceId,
        key: &DeviceRootKey,
        expires_at: OffsetDateTime,
    ) -> SignedAttestation;
}

/// Tells an account's live sessions about its devices: one registered for the first time, or
/// their KeyPackages are running out.
pub trait DeviceNotifier: Send + Sync {
    fn device_joined(&self, owner: UserId, actor: &ActorUri, device: DeviceId, key: &DeviceRootKey);
    fn key_packages_low(&self, owner: UserId);
}

/// Claims a KeyPackage from the instance hosting `target`, as the local account `sender`.
#[async_trait::async_trait]
pub trait RemoteKeyPackages: Send + Sync {
    async fn claim(
        &self,
        sender: &ActorUri,
        target: &ActorUri,
        device: Option<DeviceId>,
    ) -> Result<Claim, RemoteClaimError>;
}

/// Each MLS group's commits in epoch order: the order every member's client applies them in.
#[async_trait::async_trait]
pub trait CommitLog: Send + Sync {
    /// Store the commit at its epoch — unless another holds it already, which is returned.
    async fn append(&self, commit: &NewCommit) -> Result<Append, DeliveryStoreError>;
    /// The group's commits after `after`, in epoch order, at most `limit`.
    async fn since(
        &self,
        conversation: ConversationId,
        after: Epoch,
        limit: usize,
    ) -> Result<Vec<Commit>, DeliveryStoreError>;
}

/// Welcomes waiting for the devices they admit to groups.
#[async_trait::async_trait]
pub trait Welcomes: Send + Sync {
    async fn deposit(&self, welcome: &NewWelcome) -> Result<Welcome, DeliveryStoreError>;
    /// Every Welcome waiting for the account's device; each is handed out once.
    async fn claim(
        &self,
        recipient: UserId,
        device: DeviceId,
    ) -> Result<Vec<Welcome>, DeliveryStoreError>;
    /// Delete the Welcomes claimed before `cutoff`. How many were deleted.
    async fn delete_claimed_before(
        &self,
        cutoff: OffsetDateTime,
    ) -> Result<usize, DeliveryStoreError>;
}

/// Tells local accounts' live sessions about commits and Welcomes; a client that missed one
/// catches up on reconnect.
pub trait MlsNotifier: Send + Sync {
    fn committed(&self, to: UserId, commit: &Commit);
    fn welcome_ready(&self, to: UserId, welcome: &Welcome);
}

/// A Welcome bound for a device of an account elsewhere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutgoingWelcome {
    pub device: DeviceId,
    pub conversation: ConversationId,
    pub blob: WelcomeBlob,
    /// A group's roster, so the recipient's instance can hold the conversation — a Welcome is
    /// only key material. `None` for a DM, which both instances hold from the friendship.
    pub roster: Option<GroupSnapshot>,
}

/// Commits and Welcomes for members on other instances, best effort: nothing is sent again, and
/// a member catches up only from its own instance's log. A group's commit therefore carries its
/// roster, so it lands even ahead of the Welcome that would have brought the group there.
pub trait MlsFederation: Send + Sync {
    /// To each remote member, reached as `MessageFederation::send_to_group` reaches them;
    /// `roster` is `None` for a DM.
    fn send_commit(
        &self,
        from: &ActorUri,
        to: &[ActorUri],
        commit: &Commit,
        roster: Option<&GroupSnapshot>,
    );
    fn send_welcome(&self, from: &ActorUri, to: &RemoteActor, welcome: &OutgoingWelcome);
}

/// Each account's archive of the messages its devices decrypted, sealed under a key the server
/// never sees, and the salt that key derives from.
#[async_trait::async_trait]
pub trait HistoryArchive: Send + Sync {
    /// Store the entries the owner does not hold yet — a sibling device may have archived the
    /// same message first. How many were new.
    async fn store(
        &self,
        owner: UserId,
        entries: &[NewArchiveEntry],
    ) -> Result<usize, ArchiveStoreError>;
    /// Newest first — `(created_at, id)` descending — strictly before `after`.
    async fn page(
        &self,
        owner: UserId,
        after: Option<ArchiveCursor>,
        limit: usize,
    ) -> Result<Vec<ArchiveEntry>, ArchiveStoreError>;
    /// Delete the owner's whole archive. How many entries went.
    async fn clear(&self, owner: UserId) -> Result<usize, ArchiveStoreError>;
    async fn salt(&self, owner: UserId) -> Result<Option<ArchiveSalt>, ArchiveStoreError>;
    /// Keep `salt` unless the owner has one already: the first device's wins, and every device
    /// derives the same key. The salt now held.
    async fn set_salt_once(
        &self,
        owner: UserId,
        salt: &ArchiveSalt,
    ) -> Result<ArchiveSalt, ArchiveStoreError>;
}
