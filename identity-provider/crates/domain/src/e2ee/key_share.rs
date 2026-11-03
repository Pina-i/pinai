//! Key shares: the account's history passphrase on its way from a device holding it to an approved
//! device that doesn't — identity-provider/specs/e2ee.md § 3.11. Sealed for the recipient's HPKE
//! key and signed by the sender's root key, a share is opaque here: the instance checks who sends
//! it to whom, under which generation, and the signature, and never reads it.

use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use time::OffsetDateTime;

use crate::identity::ActorUri;
use crate::{DeviceId, ValidationError};

use super::approval::root_key_of;
use super::{
    Approval, Approver, Device, DeviceRootKey, Ed25519Signature, Ed25519Verifier,
    HistoryGeneration, HpkePublicKey, KeyDirectoryError, approval_chain, check_history_generation,
    own_unrevoked,
};

/// The largest ciphertext a share carries: the 24 words and an AEAD tag fit in it several times.
pub const KEY_SHARE_CIPHERTEXT_MAX_BYTES: usize = 1024;

/// The HPKE encapsulated key a share was sealed with: 32 bytes, DHKEM(X25519, HKDF-SHA256).
#[derive(Clone, PartialEq, Eq)]
pub struct ShareEnc([u8; 32]);

impl ShareEnc {
    pub fn parse(bytes: &[u8]) -> Result<Self, ValidationError> {
        bytes
            .try_into()
            .map(Self)
            .map_err(|_| ValidationError::new("enc", "must be 32 bytes (X25519)"))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for ShareEnc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ShareEnc(..)")
    }
}

/// The passphrase sealed for the recipient.
#[derive(Clone, PartialEq, Eq)]
pub struct ShareCiphertext(Vec<u8>);

impl ShareCiphertext {
    pub fn parse(bytes: Vec<u8>) -> Result<Self, ValidationError> {
        if bytes.is_empty() || bytes.len() > KEY_SHARE_CIPHERTEXT_MAX_BYTES {
            return Err(ValidationError::new(
                "ciphertext",
                "must be 1 to 1024 bytes",
            ));
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for ShareCiphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ShareCiphertext({} bytes)", self.0.len())
    }
}

/// What the share's HPKE seal binds as associated data: whose passphrase, from which device, to
/// which, under which generation. The `PINAI-HISTORY-SHARE-v1` tag keeps the bytes from verifying
/// as any other use of the root key; a change to these fields needs a new tag.
pub fn share_aad(
    actor: &ActorUri,
    sender: DeviceId,
    recipient: DeviceId,
    generation: HistoryGeneration,
) -> Vec<u8> {
    format!(
        "PINAI-HISTORY-SHARE-v1\n{actor}\n{sender}\n{recipient}\n{}",
        generation.value()
    )
    .into_bytes()
}

/// What the sender's root key signs: the `aad`'s lines, then the seal's two halves in base64, each
/// on a line of its own. No field holds a newline, so the seven lines split one way only.
pub fn share_signed_bytes(aad: &[u8], enc: &ShareEnc, ciphertext: &ShareCiphertext) -> Vec<u8> {
    let mut signed = aad.to_vec();
    signed.push(b'\n');
    signed.extend_from_slice(B64.encode(enc.as_bytes()).as_bytes());
    signed.push(b'\n');
    signed.extend_from_slice(B64.encode(ciphertext.as_bytes()).as_bytes());
    signed
}

/// A share as its sender sends it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedShare {
    pub enc: ShareEnc,
    pub ciphertext: ShareCiphertext,
    /// The sender's root key's, over [`share_signed_bytes`].
    pub signature: Ed25519Signature,
}

/// A share as the directory holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyShare {
    pub sender: DeviceId,
    pub recipient: DeviceId,
    pub generation: HistoryGeneration,
    pub sealed: SealedShare,
    pub created_at: OffsetDateTime,
}

/// A share whose rules held over the devices and approvals as they were read: only [`may_share`]
/// makes one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckedShare {
    sender: DeviceId,
    sender_key: DeviceRootKey,
    recipient: DeviceId,
    recipient_key: DeviceRootKey,
    recipient_hpke_key: HpkePublicKey,
    generation: HistoryGeneration,
    sealed: SealedShare,
    relied_on: Vec<Approval>,
}

impl CheckedShare {
    pub fn sender(&self) -> DeviceId {
        self.sender
    }

    /// The sender's root key, which verified the signature.
    pub fn sender_key(&self) -> &DeviceRootKey {
        &self.sender_key
    }

    pub fn recipient(&self) -> DeviceId {
        self.recipient
    }

    pub fn recipient_key(&self) -> &DeviceRootKey {
        &self.recipient_key
    }

    /// The HPKE key the share is sealed for, as the directory listed it.
    pub fn recipient_hpke_key(&self) -> &HpkePublicKey {
        &self.recipient_hpke_key
    }

    pub fn generation(&self) -> HistoryGeneration {
        self.generation
    }

    pub fn sealed(&self) -> &SealedShare {
        &self.sealed
    }

    /// The approvals that made the sender and the recipient approved: the write holds while they do.
    pub fn relied_on(&self) -> &[Approval] {
        &self.relied_on
    }
}

/// What a share is decided on, as read.
#[derive(Debug, Clone, Copy)]
pub struct ShareFacts<'a> {
    pub actor: &'a ActorUri,
    /// The calling session's device ([`super::calling_device`]): the sender.
    pub sender: &'a Device,
    /// The account's devices.
    pub devices: &'a [Device],
    /// The approvals of the account's devices.
    pub approvals: &'a [Approval],
    /// The account's current generation; `None` until a device sets one.
    pub current: Option<HistoryGeneration>,
}

/// Whether the sender may deposit `sealed` for `recipient_id`: it holds the current `generation`
/// and is approved under it; the recipient is another unrevoked device of the account, with an
/// HPKE key, approved under it too, approved by the sender itself — the one device it trusts
/// before it holds the passphrase — and not holding it yet; the sender's root key signed the
/// share. Approved is [`approval_chain`]'s structure — the instance's own check, behind each
/// device's.
pub fn may_share(
    recipient_id: DeviceId,
    generation: HistoryGeneration,
    sealed: SealedShare,
    facts: ShareFacts<'_>,
    verifier: &dyn Ed25519Verifier,
) -> Result<CheckedShare, KeyDirectoryError> {
    let sender = facts.sender;
    if recipient_id == sender.id {
        return Err(KeyDirectoryError::SelfShare);
    }
    let recipient = own_unrevoked(
        sender.owner,
        facts
            .devices
            .iter()
            .find(|device| device.id == recipient_id),
    )?;
    check_history_generation(generation, facts.current)?;
    let sender_key = root_key_of(sender)?;
    if sender.history_generation != Some(generation) {
        return Err(KeyDirectoryError::HistoryKeyNotHeld);
    }
    let by_sender = approval_chain(sender, generation, facts.devices, facts.approvals)
        .ok_or(KeyDirectoryError::SenderNotApproved)?;
    let recipient_key = root_key_of(recipient)?;
    let recipient_hpke_key = recipient
        .hpke_key
        .as_ref()
        .map(|held| held.key.clone())
        .ok_or(KeyDirectoryError::NoHpkeKey)?;
    let of_recipient = approval_chain(recipient, generation, facts.devices, facts.approvals)
        .ok_or(KeyDirectoryError::RecipientNotApproved)?;
    let by_the_sender = facts
        .approvals
        .iter()
        .find(|approval| {
            approval.device == recipient_id
                && approval.approver == Approver::Device(sender.id)
                && approval.root_key == recipient_key
        })
        .ok_or(KeyDirectoryError::NotTheApprover)?;
    if recipient.history_generation == Some(generation) {
        return Err(KeyDirectoryError::HistoryKeyHeld);
    }
    let signed = share_signed_bytes(
        &share_aad(facts.actor, sender.id, recipient_id, generation),
        &sealed.enc,
        &sealed.ciphertext,
    );
    if !verifier.verifies(&sender_key, &signed, &sealed.signature) {
        return Err(KeyDirectoryError::ShareUnsigned);
    }
    Ok(CheckedShare {
        sender: sender.id,
        sender_key,
        recipient: recipient_id,
        recipient_key,
        recipient_hpke_key,
        generation,
        sealed,
        relied_on: relied_on(
            by_sender
                .into_iter()
                .chain(of_recipient)
                .chain([by_the_sender]),
        ),
    })
}

/// Each approval once: the chains may share links.
fn relied_on<'a>(approvals: impl Iterator<Item = &'a Approval>) -> Vec<Approval> {
    let mut held: Vec<Approval> = Vec::new();
    for approval in approvals {
        if !held
            .iter()
            .any(|kept| kept.device == approval.device && kept.approver == approval.approver)
        {
            held.push(approval.clone());
        }
    }
    held
}

#[cfg(test)]
mod tests;
