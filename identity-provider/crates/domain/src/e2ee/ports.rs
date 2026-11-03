use time::OffsetDateTime;

use crate::identity::{ActorUri, RemoteActor};
use crate::messaging::GroupSnapshot;
use crate::{ApprovalRequestId, ConversationId, DeviceId, SessionId, UserId};

use super::{
    Append, Approval, ApprovalMessage, ApprovalMessageBody, ApprovalRequest, ArchiveCursor,
    ArchiveEntry, ArchiveStoreError, Attestation, AttestationExpiry, CheckedApproval, CheckedShare,
    Claim, ClaimedKeyPackage, Commit, DeliveryStoreError, Device, DeviceLabel, DeviceRootKey,
    Ed25519PublicKey, Ed25519Signature, Epoch, HeldHistoryKey, HistoryGeneration, HistoryKey,
    HpkeKeyWrite, KeyShare, KeyStoreError, MessageSeq, NewArchiveEntry, NewCommit, NewKeyPackage,
    NewWelcome, RemoteClaimError, RequestRefusal, Welcome, WelcomeBlob,
};

/// The devices accounts registered, and their attestations.
#[async_trait::async_trait]
pub trait Devices: Send + Sync {
    async fn find(&self, id: DeviceId) -> Result<Option<Device>, KeyStoreError>;
    /// The owner's devices: active ones first, each group most recently seen first.
    async fn list(&self, owner: UserId) -> Result<Vec<Device>, KeyStoreError>;
    /// Store the device's attestation and do `hpke_key` to its HPKE key, recording the device under
    /// `label` if it is new; only while the device is still as `read` (`None`: not recorded):
    /// unrevoked, with the same root key and HPKE key. Another root key than the one held drops, in
    /// the same write, the device's approvals, those it signed and the key shares it sent: none
    /// verifies any more; another root key or HPKE key, the shares sealed for it.
    async fn attest(
        &self,
        owner: UserId,
        id: DeviceId,
        label: &DeviceLabel,
        read: Option<&Device>,
        attestation: &Attestation,
        hpke_key: &HpkeKeyWrite,
    ) -> Result<Attest, KeyStoreError>;
    /// Revoke the device, drop its HPKE key, the approvals it signed and the key shares it sent or
    /// was sent, and close the approval requests it asks or answers, in one write: nothing
    /// encrypts to it again, nothing is approved through it, and nobody waits on it.
    async fn revoke(&self, owner: UserId, id: DeviceId) -> Result<Revocation, KeyStoreError>;
    /// Record that the device holds `generation` of its owner's history key, dropping the share it
    /// was sent; only while that is the owner's current generation (`check_history_generation`),
    /// and the device the owner's and unrevoked.
    async fn hold_history_key(
        &self,
        owner: UserId,
        id: DeviceId,
        generation: HistoryGeneration,
    ) -> Result<Holding, KeyStoreError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attest {
    Stored,
    /// The device changed since it was read: nothing was written.
    Stale,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Holding {
    Recorded,
    /// The generation is not the owner's current one: nothing was written.
    Stale,
    /// The device is revoked, or not the owner's: nothing was written.
    Refused,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Revocation {
    /// With the requests it closed that were still open.
    Revoked {
        closed: Vec<ApprovalRequest>,
    },
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
    /// Store a batch and mark the device seen, recording it under `label` if it is new, and
    /// relabelling a known one when `relabel`. How many were stored.
    async fn stash(
        &self,
        owner: UserId,
        device: DeviceId,
        label: &DeviceLabel,
        relabel: bool,
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
        expires_at: AttestationExpiry,
    ) -> SignedAttestation;
}

/// Checks Ed25519 signatures: what devices sign with their root keys, and the approvals made with a
/// generation's approval key.
pub trait Ed25519Verifier: Send + Sync {
    fn verifies(
        &self,
        key: &dyn Ed25519PublicKey,
        message: &[u8],
        signature: &Ed25519Signature,
    ) -> bool;
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
    /// One KeyPackage of each of `target`'s devices that has any.
    async fn claim_each_device(
        &self,
        sender: &ActorUri,
        target: &ActorUri,
    ) -> Result<Vec<Claim>, RemoteClaimError>;
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
/// never sees.
#[async_trait::async_trait]
pub trait HistoryArchive: Send + Sync {
    /// Store the entries the owner does not hold yet — a sibling device may have archived the
    /// same message first — while `generation` is the owner's current history key: a new one set
    /// meanwhile refuses them or erases them, never keeps them.
    async fn store(
        &self,
        owner: UserId,
        generation: HistoryGeneration,
        entries: &[NewArchiveEntry],
    ) -> Result<Archived, ArchiveStoreError>;
    /// Newest first — `(created_at, id)` descending — strictly before `after`.
    async fn page(
        &self,
        owner: UserId,
        after: Option<ArchiveCursor>,
        limit: usize,
    ) -> Result<Vec<ArchiveEntry>, ArchiveStoreError>;
    /// Delete the owner's whole archive; its key stays. How many entries went.
    async fn clear(&self, owner: UserId) -> Result<usize, ArchiveStoreError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Archived {
    /// How many entries were new.
    Stored(usize),
    /// The generation named is not the owner's current one: nothing was stored.
    Stale,
}

/// Each account's history key, one generation at a time.
#[async_trait::async_trait]
pub trait HistoryKeys: Send + Sync {
    async fn current(&self, owner: UserId) -> Result<Option<HeldHistoryKey>, ArchiveStoreError>;
    /// Make `key` the owner's history key if its generation follows the current one
    /// ([`HistoryGeneration::follows`]), erasing the owner's archive, the approvals made with older
    /// generations' approval keys and the key shares in the same write: the archive only ever holds
    /// the current generation, only its approval key approves, and only its passphrase is shared.
    /// `set_by` is the device whose session set it. The very key held already is a retry: nothing
    /// is written.
    async fn replace(
        &self,
        owner: UserId,
        key: &HistoryKey,
        set_by: DeviceId,
    ) -> Result<KeyReplace, ArchiveStoreError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyReplace {
    /// How many archive entries went with the generation replaced.
    Replaced { erased: usize },
    /// `key` is the one held: a retry of the write that set it.
    AlreadySet,
    /// The key doesn't follow `current` (`None`: none set) — another device got there first, say.
    /// Nothing was written.
    Conflict(Option<HistoryGeneration>),
}

/// The approvals of each account's devices.
#[async_trait::async_trait]
pub trait DeviceApprovals: Send + Sync {
    /// Store the approval while what it was checked on holds: the approved device unrevoked with
    /// the root key it binds, an approving device unrevoked with the root key that signed it, a
    /// passphrase's generation still the current one. One per approved device and approver.
    async fn approve(
        &self,
        owner: UserId,
        approval: &CheckedApproval,
    ) -> Result<Approve, KeyStoreError>;
    /// The approvals of the owner's devices, oldest first.
    async fn of_owner(&self, owner: UserId) -> Result<Vec<Approval>, KeyStoreError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Approve {
    Recorded,
    /// The approver had approved the device already: nothing was written.
    AlreadyHeld,
    /// A device or the generation changed since it was read: nothing was written.
    Stale,
}

/// The approval requests and the messages relayed over them.
#[async_trait::async_trait]
pub trait ApprovalRequests: Send + Sync {
    /// Open `request`, closing its device's open one, unless the account opened as many as
    /// [`super::may_open_request`] allows since [`super::window_start`] — counted under the
    /// account's lock, so two at once can't both pass —, or its device is no longer unrevoked.
    async fn open(&self, request: &ApprovalRequest) -> Result<Opened, KeyStoreError>;
    /// The owner's requests open at `now`, oldest first.
    async fn open_of(
        &self,
        owner: UserId,
        now: OffsetDateTime,
    ) -> Result<Vec<ApprovalRequest>, KeyStoreError>;
    /// Post `body` from `from` to the owner's request as [`ApprovalRequest::may_post`] decides on
    /// the request and its messages under the request's lock, binding it when that says so; while
    /// `from` is unrevoked.
    async fn post(
        &self,
        owner: UserId,
        id: ApprovalRequestId,
        from: &Device,
        body: &ApprovalMessageBody,
        now: OffsetDateTime,
    ) -> Result<Post, KeyStoreError>;
    /// The owner's request's messages after `after` but `reader`'s own, in order, as
    /// [`ApprovalRequest::may_read`] lets `reader` read them — decided on the request as it
    /// stands, in the same read.
    async fn read(
        &self,
        owner: UserId,
        id: ApprovalRequestId,
        reader: DeviceId,
        after: MessageSeq,
        now: OffsetDateTime,
    ) -> Result<Read, KeyStoreError>;
    /// Close the owner's request for `by`, as [`ApprovalRequest::may_take_part`] lets it.
    async fn close(
        &self,
        owner: UserId,
        id: ApprovalRequestId,
        by: DeviceId,
        now: OffsetDateTime,
    ) -> Result<Close, KeyStoreError>;
    /// Delete the requests opened before `cutoff`, their messages with them.
    async fn delete_opened_before(&self, cutoff: OffsetDateTime) -> Result<usize, KeyStoreError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Opened {
    /// The requests this one closed that were still open.
    Opened {
        closed: Vec<ApprovalRequest>,
    },
    TooMany,
    /// The device was revoked since it was read: nothing was written.
    Stale,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Post {
    /// The request as the message left it; `bound` when the message bound it to its poster.
    Posted {
        request: ApprovalRequest,
        seq: MessageSeq,
        bound: bool,
    },
    Refused(RequestRefusal),
    /// The poster was revoked since it was read: nothing was written.
    Stale,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Read {
    Messages(Vec<ApprovalMessage>),
    Refused(RequestRefusal),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Close {
    /// The request as it was when it closed.
    Closed(ApprovalRequest),
    Refused(RequestRefusal),
}

/// The account's history passphrase on its way to its devices, one share per recipient and
/// generation.
#[async_trait::async_trait]
pub trait KeyShares: Send + Sync {
    /// Store the share while what it was checked on holds: its generation the owner's current one,
    /// the sender unrevoked with the root key that signed it and holding that generation, the
    /// recipient unrevoked with the root key and HPKE key it was sealed for and not holding it, and
    /// every approval it relied on still held. The first share stored for a recipient and
    /// generation stays.
    async fn deposit(&self, owner: UserId, share: &CheckedShare) -> Result<Deposit, KeyStoreError>;
    /// The share held for the owner's device `recipient` under `generation`.
    async fn of_recipient(
        &self,
        owner: UserId,
        recipient: DeviceId,
        generation: HistoryGeneration,
    ) -> Result<Option<KeyShare>, KeyStoreError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Deposit {
    Stored,
    /// A share for the recipient and generation is held already: nothing was written.
    AlreadyHeld,
    /// A device, an approval or the generation changed since they were read: nothing was written.
    Stale,
}

/// Tells an account's live sessions about approvals, the requests relayed between its devices,
/// and the passphrase shared to them.
pub trait DeviceTrustNotifier: Send + Sync {
    /// To every live session of the account: each reads the device list again.
    fn device_approved(&self, owner: UserId, device: DeviceId);
    fn approval_requested(
        &self,
        owner: UserId,
        to: &[SessionId],
        request: &ApprovalRequest,
        display_name: &str,
    );
    fn approval_message(
        &self,
        owner: UserId,
        to: &[SessionId],
        request: ApprovalRequestId,
        seq: MessageSeq,
    );
    fn approval_closed(&self, owner: UserId, to: &[SessionId], request: ApprovalRequestId);
    /// To the recipient device's sessions: a share waits for it.
    fn history_key_ready(&self, owner: UserId, to: &[SessionId], device: DeviceId);
}
