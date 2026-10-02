//! End-to-end encryption as the server sees it: the devices accounts register and the IdP
//! attests, the KeyPackages peers claim to add those devices to MLS groups, the Delivery
//! Service — each group's commits in order, and the Welcomes waiting for their devices — and
//! each account's encrypted history archive. Every key, package, MLS message and archive entry
//! is opaque here — see identity-provider/specs/e2ee.md.

mod archive;
mod delivery;
mod device;
mod error;
mod key_package;
mod ports;
#[cfg(any(test, feature = "test-utils"))]
pub mod testing;

pub use archive::{
    ARCHIVE_BATCH_CAP, ArchiveCursor, ArchiveEntry, ArchiveNonce, ArchiveSalt, BatchSize,
    NewArchiveEntry, archive_page_size, check_archive_batch,
};
pub use delivery::{
    Append, CATCH_UP_LIMIT, CLAIMED_WELCOME_GRACE, Commit, CommitBlob, Epoch, NewCommit,
    NewWelcome, Welcome, WelcomeBlob, check_welcome, may_commit,
};
pub use device::{
    ATTESTATION_LIFETIME, Attestation, Device, DeviceKind, DeviceLabel, DeviceRootKey, Registration,
};
pub use error::{
    ArchiveError, ArchiveStoreError, DeliveryError, DeliveryStoreError, KeyDirectoryError,
    KeyStoreError, RemoteClaimError,
};
pub use key_package::{
    CLAIMED_KEY_PACKAGE_GRACE, Claim, ClaimedKeyPackage, KeyPackageBytes, KeyPackagePolicy,
    KeyPackageRefusal, NewKeyPackage,
};
pub use ports::{
    CommitLog, DeviceAttester, DeviceNotifier, Devices, HistoryArchive, KeyPackages, MlsFederation,
    MlsNotifier, OutgoingWelcome, RemoteKeyPackages, Revocation, SignedAttestation, Welcomes,
};
