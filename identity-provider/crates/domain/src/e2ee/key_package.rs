use std::fmt;

use time::{Duration, OffsetDateTime};

use crate::{DeviceId, ValidationError};

/// How long a claimed KeyPackage is kept before it is deleted.
pub const CLAIMED_KEY_PACKAGE_GRACE: Duration = Duration::days(1);

/// A TLS-encoded MLS KeyPackage as its device published it: opaque here, never empty.
#[derive(Clone, PartialEq, Eq)]
pub struct KeyPackageBytes(Vec<u8>);

impl KeyPackageBytes {
    pub fn parse(bytes: Vec<u8>) -> Result<Self, ValidationError> {
        if bytes.is_empty() {
            return Err(ValidationError::new("key_package", "is empty"));
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for KeyPackageBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyPackageBytes({} bytes)", self.0.len())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewKeyPackage {
    pub bytes: KeyPackageBytes,
    pub expires_at: OffsetDateTime,
}

/// A KeyPackage handed out to add its device to a group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimedKeyPackage {
    pub device: DeviceId,
    pub bytes: KeyPackageBytes,
    pub expires_at: OffsetDateTime,
}

/// A claim's answer: the KeyPackage, and what is left of its device's stash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    pub package: ClaimedKeyPackage,
    pub remaining: usize,
    pub needs_refill: bool,
}

/// The instance's KeyPackage limits (`E2EE_KEYPACKAGE_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyPackagePolicy {
    pub cap_per_device: usize,
    pub refill_threshold: usize,
    pub max_lifetime: Duration,
}

impl KeyPackagePolicy {
    /// The batch as it is stored: refused only when empty, every expiry set by this instance's
    /// clock. A device's clock is not ours, so a date past the lifetime, or already gone, means
    /// the device's clock is off, not that the package is bad: either one gets the full lifetime.
    pub fn admit_batch(
        &self,
        packages: Vec<NewKeyPackage>,
        now: OffsetDateTime,
    ) -> Result<Vec<NewKeyPackage>, KeyPackageRefusal> {
        if packages.is_empty() {
            return Err(KeyPackageRefusal::NoPackages);
        }
        let latest = now + self.max_lifetime;
        Ok(packages
            .into_iter()
            .map(|package| NewKeyPackage {
                expires_at: if package.expires_at <= now || package.expires_at > latest {
                    latest
                } else {
                    package.expires_at
                },
                ..package
            })
            .collect())
    }

    /// `available` is what the device holds before the upload.
    pub fn check_stash(&self, available: usize, uploading: usize) -> Result<(), KeyPackageRefusal> {
        if available + uploading > self.cap_per_device {
            return Err(KeyPackageRefusal::StashFull {
                available,
                uploading,
                cap: self.cap_per_device,
            });
        }
        Ok(())
    }

    pub fn needs_refill(&self, available: usize) -> bool {
        available <= self.refill_threshold
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyPackageRefusal {
    #[error("packages must be non-empty")]
    NoPackages,
    #[error("stash cap exceeded: have {available}, uploading {uploading}, cap is {cap}")]
    StashFull {
        available: usize,
        uploading: usize,
        cap: usize,
    },
}

#[cfg(test)]
mod tests;
