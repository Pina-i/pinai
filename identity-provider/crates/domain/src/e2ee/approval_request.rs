//! Approval requests: the relay the code handshake runs over — identity-provider/specs/e2ee.md
//! § 3.10. A new device opens one; one other device of the account takes it up; what they say to
//! each other is opaque here.

use std::fmt;

use time::{Duration, OffsetDateTime};

use crate::auth::Session;
use crate::{ApprovalRequestId, DeviceId, SessionId, UserId, ValidationError};

use super::approval::root_key_of;
use super::{Device, KeyDirectoryError};

/// How long a request stays open.
pub const APPROVAL_REQUEST_LIFETIME: Duration = Duration::minutes(10);
/// How many requests an account opens in [`APPROVAL_REQUEST_WINDOW`]: each is a guess at a code.
pub const APPROVAL_REQUESTS_PER_WINDOW: usize = 10;
pub const APPROVAL_REQUEST_WINDOW: Duration = Duration::hours(1);
/// Messages a request holds: one handshake takes a few, and another attempt is another request,
/// with a new code.
pub const APPROVAL_MESSAGES_PER_REQUEST: usize = 12;
pub const APPROVAL_MESSAGE_MAX_BYTES: usize = 4096;

/// Whether the account may open another request, `opened` being how many it opened since
/// [`window_start`].
pub fn may_open_request(opened: usize) -> Result<(), RequestRefusal> {
    if opened >= APPROVAL_REQUESTS_PER_WINDOW {
        return Err(RequestRefusal::TooMany);
    }
    Ok(())
}

/// The requests opened since then count against the account's limit; older ones are swept.
pub fn window_start(now: OffsetDateTime) -> OffsetDateTime {
    now - APPROVAL_REQUEST_WINDOW
}

/// Why a request refused what a device asked of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RequestRefusal {
    #[error("approval request not found")]
    NotFound,
    #[error("the approval request has ended")]
    Ended,
    #[error("another device is answering this approval request")]
    Taken,
    #[error("the approval request holds no more messages")]
    Full,
    #[error("too many approval requests in the last hour")]
    TooMany,
    /// Answering one ends in approving the other device, which takes a root key.
    #[error("the device has registered no root key")]
    NoRootKey,
}

/// One message of a handshake, opaque here.
#[derive(Clone, PartialEq, Eq)]
pub struct ApprovalMessageBody(Vec<u8>);

impl ApprovalMessageBody {
    pub fn parse(bytes: Vec<u8>) -> Result<Self, ValidationError> {
        if bytes.is_empty() || bytes.len() > APPROVAL_MESSAGE_MAX_BYTES {
            return Err(ValidationError::new("body", "must be 1 to 4096 bytes"));
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for ApprovalMessageBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ApprovalMessageBody({} bytes)", self.0.len())
    }
}

/// A message's place in its request, from 1; 0 is before the first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct MessageSeq(i32);

impl MessageSeq {
    pub const START: Self = Self(0);

    pub fn parse(raw: i64) -> Result<Self, ValidationError> {
        i32::try_from(raw)
            .ok()
            .filter(|seq| *seq >= 0)
            .map(Self)
            .ok_or_else(|| ValidationError::new("after", "must be from 0 to 2147483647"))
    }

    pub fn value(self) -> i32 {
        self.0
    }

    fn after(posted: usize) -> Self {
        Self(i32::try_from(posted + 1).expect("a request holds a dozen messages"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalMessage {
    pub seq: MessageSeq,
    /// The device that posted it.
    pub from: DeviceId,
    pub body: ApprovalMessageBody,
    pub created_at: OffsetDateTime,
}

/// A request a device opened to be approved by another device of the account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRequest {
    pub id: ApprovalRequestId,
    pub owner: UserId,
    /// The device asking to be approved.
    pub device: DeviceId,
    /// The device answering it: the first other device to post, `None` until one does.
    pub approver: Option<DeviceId>,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub closed_at: Option<OffsetDateTime>,
}

/// What posting a message does to its request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Posting {
    pub seq: MessageSeq,
    /// The request is now the poster's to answer.
    pub binds: bool,
}

impl ApprovalRequest {
    /// A request of `device`'s, the caller's own unrevoked one: only a device with a root key has
    /// something to be approved.
    pub fn open_for(device: &Device, now: OffsetDateTime) -> Result<Self, KeyDirectoryError> {
        root_key_of(device)?;
        Ok(Self {
            id: ApprovalRequestId::generate(),
            owner: device.owner,
            device: device.id,
            approver: None,
            created_at: now,
            expires_at: now + APPROVAL_REQUEST_LIFETIME,
            closed_at: None,
        })
    }

    pub fn is_open(&self, now: OffsetDateTime) -> bool {
        self.closed_at.is_none() && now < self.expires_at
    }

    /// Whether `device`, one of the account's, may read, post or close: the device asking, the
    /// device answering, or — until one answers — any other.
    pub fn may_take_part(
        &self,
        device: DeviceId,
        now: OffsetDateTime,
    ) -> Result<(), RequestRefusal> {
        self.not_anothers(device)?;
        if !self.is_open(now) {
            return Err(RequestRefusal::Ended);
        }
        Ok(())
    }

    /// Whether `device` may read the messages: the two sides until the request is swept — the
    /// last message may come with the close —, any other device while it is open and unanswered.
    pub fn may_read(&self, device: DeviceId, now: OffsetDateTime) -> Result<(), RequestRefusal> {
        self.not_anothers(device)?;
        if device == self.device || self.approver == Some(device) {
            return Ok(());
        }
        if !self.is_open(now) {
            return Err(RequestRefusal::Ended);
        }
        Ok(())
    }

    /// A third device is told the request is another's before anything else, ended or not.
    fn not_anothers(&self, device: DeviceId) -> Result<(), RequestRefusal> {
        match self.approver {
            Some(approver) if device != approver && device != self.device => {
                Err(RequestRefusal::Taken)
            }
            _ => Ok(()),
        }
    }

    /// What a message from `from` does, the request holding `posted` already: the first from
    /// another device than the one asking binds the request to it.
    pub fn may_post(
        &self,
        from: &Device,
        posted: usize,
        now: OffsetDateTime,
    ) -> Result<Posting, RequestRefusal> {
        self.may_take_part(from.id, now)?;
        if posted >= APPROVAL_MESSAGES_PER_REQUEST {
            return Err(RequestRefusal::Full);
        }
        let binds = self.approver.is_none() && from.id != self.device;
        if binds && from.attestation.is_none() {
            return Err(RequestRefusal::NoRootKey);
        }
        Ok(Posting {
            seq: MessageSeq::after(posted),
            binds,
        })
    }

    /// Who hears of a message from `from`: the other side — every other device, until one
    /// answers.
    pub fn counterpart(&self, from: DeviceId) -> Audience {
        if from != self.device {
            return Audience::Devices(vec![self.device]);
        }
        match self.approver {
            Some(approver) => Audience::Devices(vec![approver]),
            None => Audience::AllBut(vec![self.device]),
        }
    }

    /// Who hears that the request ended: both sides — every device, until one answers.
    pub fn parties(&self) -> Audience {
        match self.approver {
            Some(approver) => Audience::Devices(vec![self.device, approver]),
            None => Audience::AllBut(Vec::new()),
        }
    }

    /// The devices it is no longer theirs to answer, once it is bound.
    pub fn bystanders(&self) -> Audience {
        Audience::AllBut(std::iter::once(self.device).chain(self.approver).collect())
    }
}

/// Whose live sessions hear of a request: those of devices — a session that named none can't
/// take part, so it hears nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Audience {
    Devices(Vec<DeviceId>),
    AllBut(Vec<DeviceId>),
}

impl Audience {
    pub fn sessions(&self, sessions: &[Session], now: OffsetDateTime) -> Vec<SessionId> {
        sessions
            .iter()
            .filter(|session| session.is_live(now))
            .filter(|session| {
                session.device.is_some_and(|device| match self {
                    Self::Devices(devices) => devices.contains(&device),
                    Self::AllBut(devices) => !devices.contains(&device),
                })
            })
            .map(|session| session.id)
            .collect()
    }
}

#[cfg(test)]
mod tests;
