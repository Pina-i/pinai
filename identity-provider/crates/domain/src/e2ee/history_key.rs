use std::fmt;

use time::OffsetDateTime;

use crate::identity::Bearer;
use crate::{DeviceId, UserId, ValidationError};

use super::{ArchiveError, Device, KeyDirectoryError};

/// A generation of the account's history passphrase: 1 for the first, one more each time the
/// account starts over with a new one — identity-provider/specs/e2ee.md § 3.6.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HistoryGeneration(i32);

impl HistoryGeneration {
    pub const FIRST: Self = Self(1);

    pub fn parse(raw: i64) -> Result<Self, ValidationError> {
        i32::try_from(raw)
            .ok()
            .filter(|generation| *generation >= 1)
            .map(Self)
            .ok_or_else(|| ValidationError::new("generation", "must be from 1 to 2147483647"))
    }

    pub fn value(self) -> i32 {
        self.0
    }

    /// The generation this one replaces; the first replaces none.
    pub fn previous(self) -> Option<Self> {
        (self.0 > 1).then(|| Self(self.0 - 1))
    }

    /// Only the generation right after the current one is set, so two devices starting over at
    /// once make one generation.
    pub fn follows(self, current: Option<Self>) -> bool {
        self.previous() == current
    }
}

/// The random salt a generation's History Archive Key derives from, by Argon2id: 16 bytes, not
/// secret.
#[derive(Clone, PartialEq, Eq)]
pub struct HistorySalt([u8; 16]);

impl HistorySalt {
    pub fn parse(bytes: &[u8]) -> Result<Self, ValidationError> {
        bytes
            .try_into()
            .map(Self)
            .map_err(|_| ValidationError::new("salt", "must be 16 bytes"))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for HistorySalt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HistorySalt(..)")
    }
}

/// `HMAC-SHA256(key = HAK, message = "pinai/history-archive/check-v1")`, which the client
/// computes: a device tells by it whether a passphrase is the current one. The server only keeps
/// it.
#[derive(Clone, PartialEq, Eq)]
pub struct HistoryCheckValue([u8; 32]);

impl HistoryCheckValue {
    pub fn parse(bytes: &[u8]) -> Result<Self, ValidationError> {
        bytes
            .try_into()
            .map(Self)
            .map_err(|_| ValidationError::new("check_value", "must be 32 bytes (HMAC-SHA256)"))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for HistoryCheckValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HistoryCheckValue(..)")
    }
}

/// The Ed25519 public key whose 32-byte seed is
/// `HKDF-SHA256(ikm = HAK, info = "pinai/device-approval/v1")`, with no salt
/// (identity-provider/specs/e2ee.md § 3.7). The devices holding the passphrase check it against
/// their own derivation; it is never derived here.
#[derive(Clone, PartialEq, Eq)]
pub struct ApprovalPublicKey([u8; 32]);

impl ApprovalPublicKey {
    pub fn parse(bytes: &[u8]) -> Result<Self, ValidationError> {
        bytes
            .try_into()
            .map(Self)
            .map_err(|_| ValidationError::new("approval_public_key", "must be 32 bytes (Ed25519)"))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for ApprovalPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ApprovalPublicKey(..)")
    }
}

/// The account's history key: one at a time, the archive holding only entries sealed under it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryKey {
    pub generation: HistoryGeneration,
    pub salt: HistorySalt,
    pub check_value: HistoryCheckValue,
    pub approval_public_key: ApprovalPublicKey,
}

/// The history key as the account holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldHistoryKey {
    pub key: HistoryKey,
    /// The device whose session set it; `None` only once that device's row is gone.
    pub set_by: Option<DeviceId>,
}

/// A generation named that isn't the account's current one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("not the account's current history key")]
pub struct StaleHistoryKey;

/// A session that hasn't named its device, setting or holding the history key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("this session named no device")]
pub struct DeviceRequired;

/// Setting or holding a generation takes a session that named its device: the history key is
/// set by, and held on, a device the account's others can tell.
fn sessions_device(named: Option<DeviceId>) -> Result<DeviceId, DeviceRequired> {
    named.ok_or(DeviceRequired)
}

/// Who may set `generation` of the account's history key: a session that named its device — the
/// device recorded as setting it — and, past the first generation, which erases the archive saved
/// under the one before, with a recent password (`RECENT_SIGN_IN`): a token left on a device must
/// not be enough.
pub fn may_set_history_key(
    generation: HistoryGeneration,
    bearer: &Bearer,
    named: Option<DeviceId>,
    now: OffsetDateTime,
) -> Result<DeviceId, ArchiveError> {
    let device = sessions_device(named)?;
    if generation != HistoryGeneration::FIRST && !bearer.signed_in_recently(now) {
        return Err(ArchiveError::RecentSignInRequired);
    }
    Ok(device)
}

/// The archive is written, and a device said to hold the key, under the current generation only:
/// a device that missed a new one mixes no keys. `current` is `None` until a device sets one.
pub fn check_history_generation(
    named: HistoryGeneration,
    current: Option<HistoryGeneration>,
) -> Result<(), StaleHistoryKey> {
    if current != Some(named) {
        return Err(StaleHistoryKey);
    }
    Ok(())
}

/// Which device may say it holds the account's history key: the one its session named, never
/// another; an unrevoked one of the caller's — another account's id says nothing here —; and only
/// for the current generation. `device` is what the directory holds under `id`.
pub fn may_report_history_key(
    named: Option<DeviceId>,
    caller: UserId,
    id: DeviceId,
    device: Option<&Device>,
    generation: HistoryGeneration,
    current: Option<HistoryGeneration>,
) -> Result<(), KeyDirectoryError> {
    if sessions_device(named)? != id {
        return Err(KeyDirectoryError::NotTheSessionsDevice);
    }
    let device = device
        .filter(|device| device.owner == caller)
        .ok_or(KeyDirectoryError::DeviceNotFound)?;
    if device.is_revoked() {
        return Err(KeyDirectoryError::DeviceRevoked);
    }
    check_history_generation(generation, current)?;
    Ok(())
}

#[cfg(test)]
mod tests;
