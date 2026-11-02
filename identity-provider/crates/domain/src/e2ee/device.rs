use std::fmt;
use std::str::FromStr;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use time::{Duration, OffsetDateTime, UtcOffset};

use crate::auth::AuthError;
use crate::identity::ActorUri;
use crate::{DeviceId, UserId, ValidationError};

use super::{Ed25519Verifier, HistoryGeneration, KeyDirectoryError};

/// How long an attestation holds; clients renew it silently within its last 30 days.
pub const ATTESTATION_LIFETIME: Duration = Duration::days(365);

/// When an attestation expires, as its canonical bytes write it: UTC, to the second.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttestationExpiry(OffsetDateTime);

impl AttestationExpiry {
    pub fn at(self) -> OffsetDateTime {
        self.0
    }
}

/// UTC whole seconds outlive the database's microseconds — identity-provider/specs/e2ee.md § 7.2.
pub fn attestation_period(now: OffsetDateTime) -> (OffsetDateTime, AttestationExpiry) {
    let issued_at = now
        .to_offset(UtcOffset::UTC)
        .replace_nanosecond(0)
        .expect("0 is a valid nanosecond");
    (
        issued_at,
        AttestationExpiry(issued_at + ATTESTATION_LIFETIME),
    )
}

/// An Ed25519 public key signatures are checked against: a device's root key, or a generation's
/// approval key.
pub trait Ed25519PublicKey {
    fn public_bytes(&self) -> &[u8; 32];
}

/// A device's Ed25519 public key, which its IdP attests: every MLS leaf the device signs
/// chains to it.
#[derive(Clone, PartialEq, Eq)]
pub struct DeviceRootKey([u8; 32]);

impl DeviceRootKey {
    pub fn parse(bytes: &[u8]) -> Result<Self, ValidationError> {
        bytes
            .try_into()
            .map(Self)
            .map_err(|_| ValidationError::new("drk_public_key", "must be 32 bytes (Ed25519)"))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Ed25519PublicKey for DeviceRootKey {
    fn public_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for DeviceRootKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DeviceRootKey(..)")
    }
}

/// An Ed25519 signature: by a device's root key, or by a generation's approval key.
#[derive(Clone, PartialEq, Eq)]
pub struct Ed25519Signature([u8; 64]);

impl Ed25519Signature {
    /// `field` names it in the refusal: the same kind of signature signs more than one thing.
    pub fn parse(field: &'static str, bytes: &[u8]) -> Result<Self, ValidationError> {
        bytes
            .try_into()
            .map(Self)
            .map_err(|_| ValidationError::new(field, "must be 64 bytes (Ed25519)"))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Ed25519Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Ed25519Signature(..)")
    }
}

/// A device's HPKE public key — DHKEM(X25519, HKDF-SHA256) — which the account's other devices
/// encrypt to.
#[derive(Clone, PartialEq, Eq)]
pub struct HpkePublicKey([u8; 32]);

impl HpkePublicKey {
    pub fn parse(bytes: &[u8]) -> Result<Self, ValidationError> {
        bytes
            .try_into()
            .map(Self)
            .map_err(|_| ValidationError::new("hpke_public_key", "must be 32 bytes (X25519)"))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// What the device's root key signs. The `PINAI-DEVICE-HPKE-v1` tag keeps the signature from
    /// verifying as any other use of the root key; a change to these fields needs a new tag.
    pub fn canonical_bytes(&self, actor: &ActorUri, device: DeviceId) -> Vec<u8> {
        format!(
            "PINAI-DEVICE-HPKE-v1\n{actor}\n{device}\n{}",
            B64.encode(self.0)
        )
        .into_bytes()
    }
}

impl fmt::Debug for HpkePublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HpkePublicKey(..)")
    }
}

/// An HPKE key and the signature a registration sends with it, not checked yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnverifiedHpkeKey {
    key: HpkePublicKey,
    signature: Ed25519Signature,
}

impl UnverifiedHpkeKey {
    pub fn new(key: HpkePublicKey, signature: Ed25519Signature) -> Self {
        Self { key, signature }
    }

    /// A registration sends both halves, or neither.
    pub fn from_parts(
        key: Option<HpkePublicKey>,
        signature: Option<Ed25519Signature>,
    ) -> Result<Option<Self>, ValidationError> {
        match (key, signature) {
            (Some(key), Some(signature)) => Ok(Some(Self::new(key, signature))),
            (None, None) => Ok(None),
            _ => Err(ValidationError::new(
                "hpke_key_signature",
                "comes with hpke_public_key, or neither is sent",
            )),
        }
    }

    /// The key, if `root` signed it for this `device` of `actor`.
    pub fn verified(
        self,
        root: &DeviceRootKey,
        actor: &ActorUri,
        device: DeviceId,
        verifier: &dyn Ed25519Verifier,
    ) -> Result<SignedHpkeKey, KeyDirectoryError> {
        let signed = self.key.canonical_bytes(actor, device);
        if !verifier.verifies(root, &signed, &self.signature) {
            return Err(KeyDirectoryError::HpkeKeyUnsigned);
        }
        Ok(SignedHpkeKey {
            key: self.key,
            signature: self.signature,
        })
    }
}

/// A device's HPKE key with its root key's signature over the key's canonical bytes, checked:
/// only [`UnverifiedHpkeKey::verified`] makes one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedHpkeKey {
    key: HpkePublicKey,
    signature: Ed25519Signature,
}

impl SignedHpkeKey {
    pub fn key(&self) -> &HpkePublicKey {
        &self.key
    }

    pub fn signature(&self) -> &Ed25519Signature {
        &self.signature
    }
}

/// The HPKE key a device holds, as the directory reads it back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldHpkeKey {
    pub key: HpkePublicKey,
    pub signature: Ed25519Signature,
}

impl From<&SignedHpkeKey> for HeldHpkeKey {
    fn from(signed: &SignedHpkeKey) -> Self {
        Self {
            key: signed.key.clone(),
            signature: signed.signature.clone(),
        }
    }
}

/// What a registration does to the HPKE key its device holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HpkeKeyWrite {
    Keep,
    Set(SignedHpkeKey),
    Clear,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceKind {
    Laptop,
    Phone,
    Tablet,
    Unknown,
}

impl DeviceKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Laptop => "laptop",
            Self::Phone => "phone",
            Self::Tablet => "tablet",
            Self::Unknown => "unknown",
        }
    }
}

impl FromStr for DeviceKind {
    type Err = ValidationError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        match raw {
            "laptop" => Ok(Self::Laptop),
            "phone" => Ok(Self::Phone),
            "tablet" => Ok(Self::Tablet),
            "unknown" => Ok(Self::Unknown),
            _ => Err(ValidationError::new(
                "device kind",
                "laptop, phone, tablet or unknown",
            )),
        }
    }
}

/// How a device is shown in Settings → Devices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceLabel {
    pub name: String,
    pub kind: DeviceKind,
}

impl DeviceLabel {
    /// A device nothing is known about yet.
    pub fn unknown() -> Self {
        Self {
            name: "Web client".to_owned(),
            kind: DeviceKind::Unknown,
        }
    }

    /// A device recorded before its client said what it is takes the first label that says.
    pub fn replaces(&self, held: &DeviceLabel) -> bool {
        *held == Self::unknown() && *self != Self::unknown()
    }

    /// Coarse on purpose — an icon and a "Chrome on macOS" line. An iPadOS Safari claiming to be
    /// desktop Safari reads as a laptop.
    pub fn from_user_agent(user_agent: Option<&str>) -> Self {
        let Some(ua) = user_agent.filter(|ua| !ua.is_empty()) else {
            return Self::unknown();
        };
        let label = |name: String, kind| Self { name, kind };
        // Before Safari: every iOS browser says Safari too.
        if ua.contains("iPhone") {
            return label(browser_on(ua, "iOS"), DeviceKind::Phone);
        }
        if ua.contains("iPad") {
            return label(browser_on(ua, "iPadOS"), DeviceKind::Tablet);
        }
        if ua.contains("Android") {
            let kind = if ua.contains("Mobile") {
                DeviceKind::Phone
            } else {
                DeviceKind::Tablet
            };
            return label(browser_on(ua, "Android"), kind);
        }
        let os = desktop_os(ua);
        // Most specific first: Edge and Opera say Chrome too, and Chrome says Safari.
        let browser = [
            ("Edg/", "Edge"),
            ("Edge/", "Edge"),
            ("OPR/", "Opera"),
            ("Opera/", "Opera"),
            ("Firefox/", "Firefox"),
            ("Chrome/", "Chrome"),
            ("Safari/", "Safari"),
        ]
        .into_iter()
        .find(|(token, _)| ua.contains(token));
        match browser {
            Some((_, browser)) => label(format!("{browser} on {os}"), DeviceKind::Laptop),
            None => Self::unknown(),
        }
    }
}

fn desktop_os(ua: &str) -> &'static str {
    if ua.contains("Mac OS X") || ua.contains("macOS") {
        "macOS"
    } else if ua.contains("Windows") {
        "Windows"
    } else if ua.contains("Linux") {
        "Linux"
    } else {
        "this device"
    }
}

fn browser_on(ua: &str, os: &str) -> String {
    let browser = [
        ("CriOS/", "Chrome"),
        ("FxiOS/", "Firefox"),
        ("EdgiOS/", "Edge"),
        ("Firefox/", "Firefox"),
        ("Chrome/", "Chrome"),
        ("Safari/", "Safari"),
    ]
    .into_iter()
    .find(|(token, _)| ua.contains(token))
    .map_or("Browser", |(_, browser)| browser);
    format!("{browser} on {os}")
}

/// The IdP's signature binding a root key to a device of an account, until `expires_at`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attestation {
    pub root_key: DeviceRootKey,
    pub signature: Vec<u8>,
    pub kid: String,
    pub issued_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    pub id: DeviceId,
    pub owner: UserId,
    pub label: DeviceLabel,
    pub paired_at: OffsetDateTime,
    pub last_seen_at: OffsetDateTime,
    pub revoked_at: Option<OffsetDateTime>,
    /// `None` until the device registers its root key.
    pub attestation: Option<Attestation>,
    /// Signed by the attested root key; `None` until the device registers one.
    pub hpke_key: Option<HeldHpkeKey>,
    /// The generation of the account's history key the device says it holds; `None` until it
    /// says.
    pub history_generation: Option<HistoryGeneration>,
}

impl Device {
    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }

    /// Only its owner registers or stocks a device — device ids are no secret, a claim hands
    /// them out — and not once it is revoked.
    pub fn usable_by(&self, caller: UserId) -> Result<(), KeyDirectoryError> {
        if self.owner != caller {
            return Err(KeyDirectoryError::DeviceTaken);
        }
        if self.is_revoked() {
            return Err(KeyDirectoryError::DeviceRevoked);
        }
        Ok(())
    }
}

/// One of `caller`'s devices, unrevoked, from what the directory holds under its id: another
/// account's id says nothing here.
pub fn own_unrevoked(caller: UserId, found: Option<&Device>) -> Result<&Device, KeyDirectoryError> {
    let device = found
        .filter(|device| device.owner == caller)
        .ok_or(KeyDirectoryError::DeviceNotFound)?;
    if device.is_revoked() {
        return Err(KeyDirectoryError::DeviceRevoked);
    }
    Ok(device)
}

/// A session is limited to the device it declared — identity-provider/specs/auth.md § 1.
pub fn may_register(named: Option<DeviceId>, device: DeviceId) -> Result<(), KeyDirectoryError> {
    match named {
        Some(named) if named != device => Err(KeyDirectoryError::NotTheSessionsDevice),
        _ => Ok(()),
    }
}

/// The same limit on naming: a session that declared a device is never pointed at another.
pub fn may_name(named: Option<DeviceId>, device: DeviceId) -> Result<(), AuthError> {
    match named {
        Some(named) if named != device => Err(AuthError::DeviceMismatch),
        _ => Ok(()),
    }
}

/// What registering a root key is for its device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Registration {
    /// The device's first attestation: the owner's other devices then add it to their groups.
    FirstTime,
    /// The same key again: only the expiry moves.
    Renewal,
    /// Another key: KeyPackages the device built under the old one stop verifying.
    Rotation,
}

impl Registration {
    /// `existing` is the device as stored, if it is. A revoked device stays revoked: a renewal
    /// would hand a stolen device another year.
    pub fn of(
        existing: Option<&Device>,
        caller: UserId,
        key: &DeviceRootKey,
    ) -> Result<Self, KeyDirectoryError> {
        if let Some(device) = existing {
            device.usable_by(caller)?;
        }
        Ok(
            match existing.and_then(|device| device.attestation.as_ref()) {
                None => Self::FirstTime,
                Some(attestation) if attestation.root_key == *key => Self::Renewal,
                Some(_) => Self::Rotation,
            },
        )
    }

    /// A key held is kept on a renewal only, since the old root key alone signed it.
    pub fn hpke_key(self, brought: Option<SignedHpkeKey>) -> HpkeKeyWrite {
        match (brought, self) {
            (Some(brought), _) => HpkeKeyWrite::Set(brought),
            (None, Self::Renewal) => HpkeKeyWrite::Keep,
            (None, Self::FirstTime | Self::Rotation) => HpkeKeyWrite::Clear,
        }
    }
}

#[cfg(test)]
mod tests;
