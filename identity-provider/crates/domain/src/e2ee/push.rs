//! Where a device's push notices go: the relay its app names and the token the relay gave it —
//! see identity-provider/specs/push.md.

use std::fmt;

use time::{Duration, OffsetDateTime};
use url::{Host, Url};

use crate::auth::Session;
use crate::validation::ValidationError;
use crate::{DeviceId, UserId};

use super::{
    ApprovalRequest, Device, DeviceTrust, KeyDirectoryError, own_unrevoked, sessions_device,
};

/// A relay's address and a token are at most this long, in bytes.
pub const PUSH_FIELD_MAX_BYTES: usize = 512;

/// The relay a device's app hands its notices to: `https`, or `http` on a loopback host — a
/// development instance's, a journey's fake relay; the send screens the address again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushRelay(String);

impl PushRelay {
    pub fn parse(raw: &str) -> Result<Self, ValidationError> {
        let refuse = || {
            ValidationError::new(
                "relay",
                format!(
                    "an https URL of at most {PUSH_FIELD_MAX_BYTES} bytes, like https://push.example.org/send"
                ),
            )
        };
        let url = Url::parse(raw).map_err(|_| refuse())?;
        let secure = match url.scheme() {
            "https" => true,
            "http" => is_loopback(&url),
            _ => false,
        };
        let fine = secure
            && url.host().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none();
        let url = String::from(url);
        if !fine || url.len() > PUSH_FIELD_MAX_BYTES {
            return Err(refuse());
        }
        Ok(Self(url))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(Host::Domain(name)) => name == "localhost",
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

/// What the relay knows the device by: whoever holds it can notify the device, so it is never
/// written to a log.
#[derive(Clone, PartialEq, Eq)]
pub struct PushToken(String);

impl PushToken {
    /// Printable ASCII without spaces: Expo's `ExponentPushToken[…]`, FCM's and APNs' tokens.
    pub fn parse(raw: &str) -> Result<Self, ValidationError> {
        let fine = !raw.is_empty()
            && raw.len() <= PUSH_FIELD_MAX_BYTES
            && raw.bytes().all(|byte| byte.is_ascii_graphic());
        if !fine {
            return Err(ValidationError::new(
                "token",
                format!("1 to {PUSH_FIELD_MAX_BYTES} printable ASCII characters, no space"),
            ));
        }
        Ok(Self(raw.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for PushToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PushToken(…)")
    }
}

/// Where one device's notices go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushRegistration {
    pub relay: PushRelay,
    pub token: PushToken,
}

/// Who sets or removes a device's push registration: that device's own session — the notices are
/// that device's to receive —, for the caller's device, unrevoked.
pub fn may_register_push(
    named: Option<DeviceId>,
    caller: UserId,
    id: DeviceId,
    device: Option<&Device>,
) -> Result<(), KeyDirectoryError> {
    if sessions_device(named)? != id {
        return Err(KeyDirectoryError::NotTheSessionsDevice);
    }
    own_unrevoked(caller, device)?;
    Ok(())
}

/// How long a device that arrived is left to be approved, or to ask a code, before the approved
/// devices are told it waits: a device restored by the 24 words is approved by then.
pub const ARRIVAL_NOTICE_DELAY: Duration = Duration::minutes(2);

/// How long a relay keeps a notice for a phone out of reach: past that, the app shows what is
/// current when opened anyway.
pub const PUSH_NOTICE_TTL: Duration = Duration::hours(1);

/// The phone's notification channel the notices go to, which its app creates.
pub const PUSH_CHANNEL: &str = "sign-ins";

/// What a notice says: fixed words, no name nor identifier — the relay and the platform's service
/// learn only that this phone was told something then.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushNotice {
    /// A device asks a code, or arrived and waits.
    DeviceWaiting,
    /// A device asks to start the history over.
    StartOver,
}

impl PushNotice {
    pub fn kind(self) -> &'static str {
        match self {
            Self::DeviceWaiting => "device_waiting",
            Self::StartOver => "start_over",
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Self::DeviceWaiting => "Is this you?",
            Self::StartOver => "Start your history over?",
        }
    }

    pub fn body(self) -> &'static str {
        match self {
            Self::DeviceWaiting => {
                "A device is signing in to your account. Open Pīna'i to approve it or sign it out."
            }
            Self::StartOver => {
                "Someone asked to start your history over. If it wasn't you, open Pīna'i to cancel it."
            }
        }
    }

    /// A notice replaces the one of its kind shown already: a device's arrival then its code
    /// leave one.
    pub fn tag(self) -> &'static str {
        self.kind()
    }
}

/// What happened, on its way to the devices to tell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PushAlert {
    pub owner: UserId,
    /// The device it is about, never told.
    pub device: DeviceId,
    pub what: Happened,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Happened {
    /// Registered for the first time: told only if it still waits [`ARRIVAL_NOTICE_DELAY`] on.
    Arrived,
    /// Opened an approval request.
    AsksACode,
    /// Asked to start the history over.
    AsksToStartOver,
}

impl PushAlert {
    pub fn notice(&self) -> PushNotice {
        match self.what {
            Happened::Arrived | Happened::AsksACode => PushNotice::DeviceWaiting,
            Happened::AsksToStartOver => PushNotice::StartOver,
        }
    }
}

/// Who is sent a notice about `concerned`: the devices approved under the current generation —
/// they can answer —, with a live session that named them — one signed out would open on a
/// sign-in —, and a registration; never `concerned` itself.
pub fn push_recipients<'a>(
    trust: &DeviceTrust,
    held: &'a [(DeviceId, PushRegistration)],
    sessions: &[Session],
    concerned: DeviceId,
    now: OffsetDateTime,
) -> Vec<&'a (DeviceId, PushRegistration)> {
    held.iter()
        .filter(|(id, _)| *id != concerned && trust.is_approved(*id))
        .filter(|(id, _)| {
            sessions
                .iter()
                .any(|session| session.device == Some(*id) && session.is_live(now))
        })
        .collect()
}

/// Whether a device that arrived still waits: known, unrevoked, not approved, and asking no code —
/// a request's own notice went as it opened.
pub fn arrival_still_waits(
    trust: &DeviceTrust,
    device: DeviceId,
    open_requests: &[ApprovalRequest],
) -> bool {
    trust.device(device).is_some_and(|held| !held.is_revoked())
        && !trust.is_approved(device)
        && !open_requests.iter().any(|request| request.device == device)
}

#[cfg(test)]
mod tests;
