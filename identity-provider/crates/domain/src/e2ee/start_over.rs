//! Start over requests: a device the account's devices haven't approved asks to set the next
//! generation of the history key, and may once no approved device has been used for a week —
//! identity-provider/specs/e2ee.md § 3.12. A password alone then never starts the history over
//! while the user uses any of their devices, and any of them cancels the request.

use std::str::FromStr;

use time::{Duration, OffsetDateTime};

use crate::auth::{SESSION_RETENTION, Session};
use crate::{DeviceId, StartOverRequestId, UserId, ValidationError};

use super::approval::root_key_of;
use super::{
    ApprovalRequired, Audience, Device, DeviceTrust, HistoryGeneration, KeyDirectoryError,
};

/// How long the approved devices must all go unused before a request matures.
pub const START_OVER_WAIT: Duration = Duration::days(7);
/// How many requests an account opens in [`START_OVER_WINDOW`]: each one tells every approved
/// device.
pub const START_OVER_REQUESTS_PER_WINDOW: usize = 3;
pub const START_OVER_WINDOW: Duration = Duration::days(1);
/// How long a request that ended is kept: its device reads how it ended after a reload.
pub const START_OVER_KEPT: Duration = Duration::days(7);

// A request is swept only once it no longer counts against the daily limit.
const _: () = assert!(START_OVER_KEPT.whole_seconds() >= START_OVER_WINDOW.whole_seconds());
// A session swept took a last use older than the wait with it, or a request would mature early.
const _: () = assert!(SESSION_RETENTION.whole_seconds() >= START_OVER_WAIT.whole_seconds());

/// The requests opened since then count against the account's limit.
pub fn start_over_window(now: OffsetDateTime) -> OffsetDateTime {
    now - START_OVER_WINDOW
}

/// The requests that ended before then are swept.
pub fn start_over_sweep_before(now: OffsetDateTime) -> OffsetDateTime {
    now - START_OVER_KEPT
}

/// How a request ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartOverEnd {
    /// By an approved device.
    Cancelled,
    /// By the device asking.
    Withdrawn,
    /// Its device set the next generation with it.
    Used,
    /// Another write set the next generation.
    Superseded,
    /// Its device was revoked.
    Revoked,
    /// Its device was approved under the generation it would replace: it needs none.
    Approved,
}

impl StartOverEnd {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cancelled => "cancelled",
            Self::Withdrawn => "withdrawn",
            Self::Used => "used",
            Self::Superseded => "superseded",
            Self::Revoked => "revoked",
            Self::Approved => "approved",
        }
    }
}

impl FromStr for StartOverEnd {
    type Err = ValidationError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        match raw {
            "cancelled" => Ok(Self::Cancelled),
            "withdrawn" => Ok(Self::Withdrawn),
            "used" => Ok(Self::Used),
            "superseded" => Ok(Self::Superseded),
            "revoked" => Ok(Self::Revoked),
            "approved" => Ok(Self::Approved),
            _ => Err(ValidationError::new(
                "ended_reason",
                "cancelled, withdrawn, used, superseded, revoked or approved",
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StartOverEnding {
    pub how: StartOverEnd,
    pub at: OffsetDateTime,
}

/// Why a start over request, or the generation it would allow, was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StartOverRefusal {
    /// The first generation is set without one.
    #[error("the account has no history key to start over from")]
    NoHistoryKey,
    #[error("an approved device replaces the history key itself")]
    AlreadyApproved,
    #[error("another device of the account is starting over")]
    Pending,
    #[error("too many start over requests in the last day")]
    TooMany,
    #[error("start over request not found")]
    NotFound,
    #[error("the start over request has ended")]
    Ended,
    /// A device not approved sets the next generation through a request of its own.
    #[error("this device starts over through a request")]
    Required,
    #[error("the start over request is not ready")]
    NotReady { ready_at: OffsetDateTime },
}

/// A device's request to set the generation after `generation`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartOverRequest {
    pub id: StartOverRequestId,
    pub owner: UserId,
    /// The device asking.
    pub device: DeviceId,
    /// The generation it would replace: the account's when it opened.
    pub generation: HistoryGeneration,
    pub created_at: OffsetDateTime,
    pub ended: Option<StartOverEnding>,
}

impl StartOverRequest {
    /// A request of `device`'s, the caller's own unrevoked one: it has a root key — the
    /// generation it sets records it, and its words approve it —, the account has a key to start
    /// over from, and the device isn't approved under it — an approved one replaces it at once.
    pub fn open_for(
        device: &Device,
        trust: &DeviceTrust,
        now: OffsetDateTime,
    ) -> Result<Self, KeyDirectoryError> {
        root_key_of(device)?;
        let generation = trust.current.ok_or(StartOverRefusal::NoHistoryKey)?;
        if trust.chain_under(device.id, generation).is_some() {
            return Err(StartOverRefusal::AlreadyApproved.into());
        }
        Ok(Self {
            id: StartOverRequestId::generate(),
            owner: device.owner,
            device: device.id,
            generation,
            created_at: now,
            ended: None,
        })
    }

    pub fn is_open(&self) -> bool {
        self.ended.is_none()
    }

    /// When it matures, as of the sessions' last uses: see [`ready_at`].
    pub fn ready_at(&self, trust: &DeviceTrust, sessions: &[Session]) -> OffsetDateTime {
        let approved = trust.approved_under(self.generation);
        ready_at(self.created_at, &approved, last_use(&approved, sessions))
    }

    /// The device asking reads it, and so do the approved devices, which may cancel it.
    pub fn may_read(&self, by: DeviceId, trust: &DeviceTrust) -> Result<(), ApprovalRequired> {
        if by == self.device || trust.chain_under(by, self.generation).is_some() {
            return Ok(());
        }
        Err(ApprovalRequired)
    }

    /// How `by` ends it: its device withdraws it, an approved device cancels it — no recent
    /// password, so that it is quick —, anyone else is refused.
    pub fn may_end(
        &self,
        by: DeviceId,
        trust: &DeviceTrust,
    ) -> Result<StartOverEnd, KeyDirectoryError> {
        if !self.is_open() {
            return Err(StartOverRefusal::Ended.into());
        }
        if by == self.device {
            return Ok(StartOverEnd::Withdrawn);
        }
        if trust.chain_under(by, self.generation).is_some() {
            return Ok(StartOverEnd::Cancelled);
        }
        Err(ApprovalRequired.into())
    }

    /// Who hears that it ended: the device asking, and the approved devices whose prompt goes.
    pub fn audience(&self, trust: &DeviceTrust) -> Audience {
        let mut devices = vec![self.device];
        devices.extend(trust.approved_under(self.generation));
        Audience::Devices(devices)
    }
}

/// The latest use of a session — signed out since or not — of any of `devices`.
pub fn last_use(devices: &[DeviceId], sessions: &[Session]) -> Option<OffsetDateTime> {
    sessions
        .iter()
        .filter(|session| {
            session
                .device
                .is_some_and(|device| devices.contains(&device))
        })
        .map(|session| session.last_used_at)
        .max()
}

/// A request opened at `created_at` matures [`START_OVER_WAIT`] after the later of its opening and
/// the last use of an approved device — at once when no device is approved: nobody is left to
/// cancel it.
pub fn ready_at(
    created_at: OffsetDateTime,
    approved: &[DeviceId],
    last_use: Option<OffsetDateTime>,
) -> OffsetDateTime {
    if approved.is_empty() {
        return created_at;
    }
    created_at.max(last_use.unwrap_or(created_at)) + START_OVER_WAIT
}

/// What opening `request` comes to, the account holding `open` and having opened `opened` since
/// [`start_over_window`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartOverOpening {
    Open,
    /// The device asked already: its open request answers.
    Existing(StartOverRequest),
}

/// One open request an account: the device asking again gets its own back, another device is
/// refused; and a few a day.
pub fn may_open_start_over(
    request: &StartOverRequest,
    open: Option<&StartOverRequest>,
    opened: usize,
) -> Result<StartOverOpening, StartOverRefusal> {
    match open {
        Some(open) if open.device == request.device => Ok(StartOverOpening::Existing(open.clone())),
        Some(_) => Err(StartOverRefusal::Pending),
        None if opened >= START_OVER_REQUESTS_PER_WINDOW => Err(StartOverRefusal::TooMany),
        None => Ok(StartOverOpening::Open),
    }
}

/// The matured request a generation is set through: only [`super::may_replace_history_key`]
/// makes one, and the write that sets it uses it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaturedStartOver {
    pub(super) request: StartOverRequestId,
    pub(super) device: DeviceId,
    pub(super) generation: HistoryGeneration,
}

impl MaturedStartOver {
    pub fn request(&self) -> StartOverRequestId {
        self.request
    }

    pub fn device(&self) -> DeviceId {
        self.device
    }

    /// The generation it replaces.
    pub fn generation(&self) -> HistoryGeneration {
        self.generation
    }
}

#[cfg(test)]
mod tests;
