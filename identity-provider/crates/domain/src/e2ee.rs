//! End-to-end encryption as the server sees it: the devices accounts register and the IdP
//! attests, the KeyPackages peers claim to add those devices to MLS groups, the Delivery
//! Service — each group's commits in order, and the Welcomes waiting for their devices — and
//! each account's encrypted history archive, with the key it is sealed under. Every key,
//! package, MLS message and archive entry is opaque here — see identity-provider/specs/e2ee.md.

mod archive;
mod delivery;
mod device;
mod error;
mod history_key;
mod key_package;
mod ports;
#[cfg(any(test, feature = "test-utils"))]
pub mod testing;

pub use archive::{
    ARCHIVE_BATCH_CAP, ArchiveCursor, ArchiveEntry, ArchiveNonce, BatchSize, NewArchiveEntry,
    archive_page_size, check_archive_batch,
};
pub use delivery::{
    Append, CATCH_UP_LIMIT, CLAIMED_WELCOME_GRACE, Commit, CommitBlob, Epoch, NewCommit,
    NewWelcome, Welcome, WelcomeBlob, check_welcome, may_commit,
};
pub use device::{
    ATTESTATION_LIFETIME, Attestation, AttestationExpiry, Device, DeviceKind, DeviceLabel,
    DeviceRootKey, HeldHpkeKey, HpkeKeyWrite, HpkePublicKey, Registration, RootKeySignature,
    SignedHpkeKey, UnverifiedHpkeKey, attestation_period, may_name, may_register,
};
pub use error::{
    ArchiveError, ArchiveStoreError, DeliveryError, DeliveryStoreError, KeyDirectoryError,
    KeyStoreError, RemoteClaimError,
};
pub use history_key::{
    ApprovalPublicKey, DeviceRequired, HeldHistoryKey, HistoryCheckValue, HistoryGeneration,
    HistoryKey, HistorySalt, StaleHistoryKey, check_history_generation, may_report_history_key,
    may_set_history_key,
};
pub use key_package::{
    CLAIMED_KEY_PACKAGE_GRACE, Claim, ClaimedKeyPackage, KeyPackageBytes, KeyPackagePolicy,
    KeyPackageRefusal, NewKeyPackage,
};
pub use ports::{
    Archived, Attest, CommitLog, DeviceAttester, DeviceNotifier, Devices, HistoryArchive,
    HistoryKeys, Holding, KeyPackages, KeyReplace, MlsFederation, MlsNotifier, OutgoingWelcome,
    RemoteKeyPackages, Revocation, RootKeyVerifier, SignedAttestation, Welcomes,
};
