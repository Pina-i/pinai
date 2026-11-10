//! End-to-end encryption as the server sees it: the devices accounts register and the IdP
//! attests, the KeyPackages peers claim to add those devices to MLS groups, the Delivery
//! Service — each group's commits in order, its newest GroupInfo, and the Welcomes waiting for
//! their devices — and
//! each account's encrypted history archive, with the key it is sealed under; the approvals the
//! account's devices give each other, the requests their handshake is relayed over, the
//! passphrase shared between them, and the requests to start the history over. Every key,
//! package, MLS message, archive entry, handshake message and key share is opaque here — see
//! identity-provider/specs/e2ee.md.

mod approval;
mod approval_request;
mod archive;
mod delivery;
mod device;
mod error;
mod history_key;
mod key_package;
mod key_share;
mod ports;
mod start_over;
#[cfg(any(test, feature = "test-utils"))]
pub mod testing;
mod trust;

pub use approval::{
    Approval, ApprovalBy, ApprovalFacts, Approver, CheckedApproval, approval_bytes, approval_chain,
    calling_device, may_approve,
};
pub use approval_request::{
    APPROVAL_MESSAGE_MAX_BYTES, APPROVAL_MESSAGES_PER_REQUEST, APPROVAL_REQUEST_LIFETIME,
    APPROVAL_REQUEST_WINDOW, APPROVAL_REQUESTS_PER_WINDOW, ApprovalMessage, ApprovalMessageBody,
    ApprovalRequest, Audience, MessageSeq, Posting, RequestRefusal, may_open_request, window_start,
};
pub use archive::{
    ARCHIVE_BATCH_CAP, ArchiveCursor, ArchiveEntry, ArchiveNonce, BatchSize, NewArchiveEntry,
    archive_page_size, check_archive_batch,
};
pub use delivery::{
    Append, CATCH_UP_LIMIT, CLAIMED_WELCOME_GRACE, Commit, CommitBlob, CommitKind, Epoch,
    GroupInfo, GroupInfoBlob, NewCommit, NewWelcome, Welcome, WelcomeBlob, check_welcome,
    may_commit, may_commit_externally,
};
pub use device::{
    ATTESTATION_LIFETIME, Attestation, AttestationExpiry, Device, DeviceKind, DeviceLabel,
    DeviceRootKey, Ed25519PublicKey, Ed25519Signature, HeldHpkeKey, HpkeKeyWrite, HpkePublicKey,
    Registration, SignedHpkeKey, UnverifiedHpkeKey, attestation_period, may_register,
    own_unrevoked,
};
pub use error::{
    ArchiveError, ArchiveStoreError, DeliveryError, DeliveryStoreError, KeyDirectoryError,
    KeyStoreError, RemoteClaimError,
};
pub use history_key::{
    ApprovalPublicKey, DeviceRequired, HeldHistoryKey, HistoryCheckValue, HistoryGeneration,
    HistoryKey, HistorySalt, KeyGate, StaleHistoryKey, check_history_generation,
    may_replace_history_key, may_report_history_key, may_set_history_key, sessions_device,
};
pub use key_package::{
    CLAIMED_KEY_PACKAGE_GRACE, Claim, ClaimedKeyPackage, KeyPackageBytes, KeyPackagePolicy,
    KeyPackageRefusal, NewKeyPackage,
};
pub use key_share::{
    CheckedShare, KEY_SHARE_CIPHERTEXT_MAX_BYTES, KeyShare, SealedShare, ShareCiphertext, ShareEnc,
    ShareFacts, may_share, share_aad, share_signed_bytes,
};
pub use ports::{
    ApprovalRequests, Approve, Archived, Attest, Cleared, Close, CommitLog, Deposit,
    DeviceApprovals, DeviceAttester, DeviceNotifier, DeviceTrustNotifier, Devices, Ed25519Verifier,
    GroupInfos, HistoryArchive, HistoryKeys, Holding, KeyPackages, KeyReplace, KeyShares,
    MlsFederation, MlsNotifier, Opened, OutgoingWelcome, Post, Read, RemoteKeyPackages, Revocation,
    SignedAttestation, StartOverEnded, StartOverOpened, StartOverRequests, Welcomes,
};
pub use start_over::{
    MaturedStartOver, START_OVER_KEPT, START_OVER_WAIT, StartOverEnd, StartOverEnding,
    StartOverOpening, StartOverRefusal, StartOverRequest, may_open_start_over,
    start_over_sweep_before, start_over_window,
};
pub use trust::{ApprovalRequired, DeviceTrust, may_act_beyond_the_password, may_revoke};
