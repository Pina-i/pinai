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
    /// A batch is refused whole, at its first bad entry.
    pub fn check_batch(
        &self,
        packages: &[NewKeyPackage],
        now: OffsetDateTime,
    ) -> Result<(), KeyPackageRefusal> {
        if packages.is_empty() {
            return Err(KeyPackageRefusal::NoPackages);
        }
        for (i, package) in packages.iter().enumerate() {
            let lifetime = package.expires_at - now;
            if lifetime > self.max_lifetime {
                return Err(KeyPackageRefusal::LivesTooLong(i));
            }
            if lifetime <= Duration::ZERO {
                return Err(KeyPackageRefusal::Expired(i));
            }
        }
        Ok(())
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
    #[error("packages[{0}].expires_at exceeds the maximum allowed lifetime")]
    LivesTooLong(usize),
    #[error("packages[{0}].expires_at is in the past")]
    Expired(usize),
    #[error("stash cap exceeded: have {available}, uploading {uploading}, cap is {cap}")]
    StashFull {
        available: usize,
        uploading: usize,
        cap: usize,
    },
}

#[cfg(test)]
mod tests;
