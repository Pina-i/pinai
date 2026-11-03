//! Approvals: one of the account's devices vouching for another's root key, or the passphrase
//! vouching for the device it was typed on — identity-provider/specs/e2ee.md § 3.9. The instance
//! stores them and refuses malformed ones; whether a device is approved, each device decides.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use time::OffsetDateTime;

use crate::identity::ActorUri;
use crate::{DeviceId, UserId};

use super::{
    Device, DeviceRootKey, Ed25519Signature, Ed25519Verifier, HistoryGeneration, HistoryKey,
    KeyDirectoryError, StaleHistoryKey, check_history_generation, own_unrevoked,
};

/// What an approval signs: the approved device and the root key it binds. The
/// `PINAI-DEVICE-APPROVAL-v1` tag keeps the signature from verifying as any other use of the key;
/// a change to these fields needs a new tag.
pub fn approval_bytes(actor: &ActorUri, device: DeviceId, root: &DeviceRootKey) -> Vec<u8> {
    format!(
        "PINAI-DEVICE-APPROVAL-v1\n{actor}\n{device}\n{}",
        B64.encode(root.as_bytes())
    )
    .into_bytes()
}

/// Who vouches for a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Approver {
    /// Another device of the account, with its root key.
    Device(DeviceId),
    /// The passphrase typed on the device itself, with that generation's approval key.
    Passphrase(HistoryGeneration),
}

/// An approval as the directory holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approval {
    pub device: DeviceId,
    /// The approved device's root key when it was approved: the one it holds still, as a new root
    /// key drops the device's approvals.
    pub root_key: DeviceRootKey,
    pub approver: Approver,
    pub signature: Ed25519Signature,
    pub created_at: OffsetDateTime,
}

/// What an approval is signed with, as the request says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalBy {
    /// The root key of the calling session's device.
    Device,
    /// The approval key of the passphrase's `generation`, approving the calling session's device.
    Passphrase(HistoryGeneration),
}

/// An approval whose signature verified over the devices as they were read: only
/// [`may_approve`] makes one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckedApproval {
    device: DeviceId,
    root_key: DeviceRootKey,
    approver: Approver,
    approver_key: Option<DeviceRootKey>,
    signature: Ed25519Signature,
}

impl CheckedApproval {
    pub fn device(&self) -> DeviceId {
        self.device
    }

    pub fn root_key(&self) -> &DeviceRootKey {
        &self.root_key
    }

    pub fn approver(&self) -> Approver {
        self.approver
    }

    /// The approving device's root key that verified the signature; `None` for the passphrase.
    pub fn approver_key(&self) -> Option<&DeviceRootKey> {
        self.approver_key.as_ref()
    }

    pub fn signature(&self) -> &Ed25519Signature {
        &self.signature
    }
}

/// The device the calling session named, as the directory holds it under that id: every approval
/// route takes one, the caller's and unrevoked.
pub fn calling_device(caller: UserId, found: Option<Device>) -> Result<Device, KeyDirectoryError> {
    own_unrevoked(caller, found.as_ref()).cloned()
}

/// What an approval is decided on, as read.
#[derive(Debug, Clone, Copy)]
pub struct ApprovalFacts<'a> {
    pub actor: &'a ActorUri,
    /// The calling session's device ([`calling_device`]): the approver, or the device the
    /// passphrase approves.
    pub signer: &'a Device,
    /// What the directory holds under the approved device's id.
    pub approved: Option<&'a Device>,
    /// The account's current history key.
    pub current: Option<&'a HistoryKey>,
}

/// Whether `signature` approves the device `approved_id`, signed as `by` says: a device approves
/// another unrevoked device of the account with its root key, and the passphrase approves the
/// device it is typed on with the current generation's approval key. Either way the signature is
/// over the approved device's root key as held; the instance never decides whom to trust.
pub fn may_approve(
    approved_id: DeviceId,
    by: ApprovalBy,
    signature: Ed25519Signature,
    facts: ApprovalFacts<'_>,
    verifier: &dyn Ed25519Verifier,
) -> Result<CheckedApproval, KeyDirectoryError> {
    let signer = facts.signer;
    match by {
        ApprovalBy::Device => {
            if approved_id == signer.id {
                return Err(KeyDirectoryError::SelfApproval);
            }
            let approved = own_unrevoked(signer.owner, facts.approved)?;
            let root_key = root_key_of(approved)?;
            let approver_key = root_key_of(signer)?;
            if !verifier.verifies(
                &approver_key,
                &approval_bytes(facts.actor, approved_id, &root_key),
                &signature,
            ) {
                return Err(KeyDirectoryError::ApprovalUnsigned);
            }
            Ok(CheckedApproval {
                device: approved_id,
                root_key,
                approver: Approver::Device(signer.id),
                approver_key: Some(approver_key),
                signature,
            })
        }
        ApprovalBy::Passphrase(generation) => {
            if approved_id != signer.id {
                return Err(KeyDirectoryError::NotTheSessionsDevice);
            }
            let root_key = root_key_of(signer)?;
            let current = facts.current.ok_or(StaleHistoryKey)?;
            check_history_generation(generation, Some(current.generation))?;
            if !verifier.verifies(
                &current.approval_public_key,
                &approval_bytes(facts.actor, approved_id, &root_key),
                &signature,
            ) {
                return Err(KeyDirectoryError::ApprovalUnsigned);
            }
            Ok(CheckedApproval {
                device: approved_id,
                root_key,
                approver: Approver::Passphrase(generation),
                approver_key: None,
                signature,
            })
        }
    }
}

/// The stored approvals that make `device` approved under `generation`: its own by that
/// generation's approval key, or one by another unrevoked device of the account carrying such an
/// approval — two links at most (identity-provider/specs/e2ee.md § 3.9). Each binds the root key
/// its device holds. Their signatures were checked as they were stored, so this reads their
/// structure only: the instance's backstop to the devices' own checks. `None` when the device, or
/// every chain to it, is no longer approved.
pub fn approval_chain<'a>(
    device: &Device,
    generation: HistoryGeneration,
    devices: &[Device],
    approvals: &'a [Approval],
) -> Option<Vec<&'a Approval>> {
    if let Some(own) = by_passphrase(device, generation, approvals) {
        return Some(vec![own]);
    }
    approvals
        .iter()
        .filter(|approval| binds(approval, device))
        .find_map(|approval| {
            let Approver::Device(by) = approval.approver else {
                return None;
            };
            let approver = devices
                .iter()
                .find(|other| other.id == by && other.owner == device.owner)?;
            by_passphrase(approver, generation, approvals).map(|theirs| vec![approval, theirs])
        })
}

fn by_passphrase<'a>(
    device: &Device,
    generation: HistoryGeneration,
    approvals: &'a [Approval],
) -> Option<&'a Approval> {
    approvals.iter().find(|approval| {
        binds(approval, device) && approval.approver == Approver::Passphrase(generation)
    })
}

/// An approval of the unrevoked `device`'s root key as it holds it now.
fn binds(approval: &Approval, device: &Device) -> bool {
    approval.device == device.id
        && !device.is_revoked()
        && device
            .attestation
            .as_ref()
            .is_some_and(|held| held.root_key == approval.root_key)
}

pub(super) fn root_key_of(device: &Device) -> Result<DeviceRootKey, KeyDirectoryError> {
    device
        .attestation
        .as_ref()
        .map(|attestation| attestation.root_key.clone())
        .ok_or(KeyDirectoryError::NoRootKey)
}

#[cfg(test)]
mod tests;
