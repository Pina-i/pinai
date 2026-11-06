//! Which of the account's devices the instance counts as approved — [`approval_chain`]'s structure
//! over the stored approvals, identity-provider/specs/e2ee.md § 3.11 — and what that gates on the
//! instance itself: revoking an approved device, starting over (§ 3.12), turning the second factor
//! on, saving to and clearing the history backup, signing the other devices out.

use crate::DeviceId;

use super::{Approval, Device, HistoryGeneration, approval_chain};

/// The account's devices, their approvals and its current generation, read together.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceTrust {
    pub devices: Vec<Device>,
    pub approvals: Vec<Approval>,
    /// `None` until a device sets the first generation.
    pub current: Option<HistoryGeneration>,
}

impl DeviceTrust {
    /// The approvals that make `device` approved under `generation`, as [`approval_chain`] reads
    /// them: unrevoked, each binding the root key its device holds.
    pub fn chain_under(
        &self,
        device: DeviceId,
        generation: HistoryGeneration,
    ) -> Option<Vec<&Approval>> {
        let device = self.devices.iter().find(|held| held.id == device)?;
        approval_chain(device, generation, &self.devices, &self.approvals)
    }

    pub fn approved_under(&self, generation: HistoryGeneration) -> Vec<DeviceId> {
        self.devices
            .iter()
            .filter(|device| self.chain_under(device.id, generation).is_some())
            .map(|device| device.id)
            .collect()
    }

    /// Approved under the current generation; with none set, no device is.
    pub fn is_approved(&self, device: DeviceId) -> bool {
        self.current
            .is_some_and(|generation| self.chain_under(device, generation).is_some())
    }

    pub fn device(&self, id: DeviceId) -> Option<&Device> {
        self.devices.iter().find(|device| device.id == id)
    }
}

/// What only a device approved under the current generation may do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("this takes a device approved under the current history key")]
pub struct ApprovalRequired;

/// Whether the session whose device is `by` may revoke `target`, one of the account's: anything
/// while the account has no history key; otherwise itself, a device not approved, or — from an
/// approved device only — an approved one. A password alone then revokes nothing approved.
pub fn may_revoke(
    target: DeviceId,
    by: Option<DeviceId>,
    trust: &DeviceTrust,
) -> Result<(), ApprovalRequired> {
    if trust.current.is_none() || by == Some(target) || !trust.is_approved(target) {
        return Ok(());
    }
    may_act_beyond_the_password(by, trust)
}

/// Whether a session whose device is `named` may do what a password alone must not: turn the
/// second factor on, which would lock the user's devices out of signing in until a start over
/// matures; save to the history backup, whose first entry under a message id is the one kept, or
/// clear it — a device added later restores from it; sign the other devices out. With a history
/// key, only from an approved device; with none, no device is approved and any session may.
pub fn may_act_beyond_the_password(
    named: Option<DeviceId>,
    trust: &DeviceTrust,
) -> Result<(), ApprovalRequired> {
    if trust.current.is_none() || named.is_some_and(|named| trust.is_approved(named)) {
        return Ok(());
    }
    Err(ApprovalRequired)
}

#[cfg(test)]
mod tests;
