use std::fmt;
use std::str::FromStr;

use time::{Duration, OffsetDateTime};

use crate::{DeviceId, UserId, ValidationError};

use super::KeyDirectoryError;

/// How long an attestation holds; clients renew it silently within its last 30 days.
pub const ATTESTATION_LIFETIME: Duration = Duration::days(365);

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

impl fmt::Debug for DeviceRootKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DeviceRootKey(..)")
    }
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
}

#[cfg(test)]
mod tests;
