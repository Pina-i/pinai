//! Approvals of the account's devices, and the requests their code handshake is relayed over —
//! identity-provider/specs/e2ee.md § 3.9–3.10.

use std::sync::Arc;

use domain::auth::{Session, Sessions};
use domain::e2ee::{
    ApprovalBy, ApprovalFacts, ApprovalMessage, ApprovalMessageBody, ApprovalNotifier,
    ApprovalRequest, ApprovalRequests, Approve, Audience, Close, Device, DeviceApprovals, Devices,
    Ed25519Signature, Ed25519Verifier, HistoryKeys, KeyDirectoryError, MessageSeq, Opened, Post,
    Read, RequestRefusal, calling_device, may_approve, sessions_device, window_start,
};
use domain::identity::{Accounts, Bearer};
use domain::{ApprovalRequestId, DeviceId, UserId};
use time::OffsetDateTime;

use crate::auth::calling_session;

/// A revoke, a new root key or a new generation may land between the reads and the write: each
/// attempt reads them again.
const ATTEMPTS: usize = 3;

/// The device the bearer's session named, the caller's and unrevoked: every route here takes one.
async fn the_callers_device(
    sessions: &dyn Sessions,
    devices: &dyn Devices,
    bearer: &Bearer,
) -> Result<Device, KeyDirectoryError> {
    let session = calling_session(sessions, bearer)
        .await
        .map_err(|e| KeyDirectoryError::Unexpected(e.into()))?;
    let named = sessions_device(session.device)?;
    calling_device(bearer.user, devices.find(named).await?)
}

/// Why a write found the caller's device changed: read again, it says how — revoked, mostly.
async fn revoked_meanwhile(
    sessions: &dyn Sessions,
    devices: &dyn Devices,
    bearer: &Bearer,
) -> KeyDirectoryError {
    match the_callers_device(sessions, devices, bearer).await {
        Err(refusal) => refusal,
        Ok(_) => KeyDirectoryError::DeviceRevoked,
    }
}

async fn sessions_of(
    sessions: &dyn Sessions,
    owner: UserId,
) -> Result<Vec<Session>, KeyDirectoryError> {
    sessions
        .of_user(owner)
        .await
        .map_err(|e| KeyDirectoryError::Unexpected(e.into()))
}

/// `POST /api/keys/devices/{device_id}/approvals`: the calling session's device approves another
/// device of the account, or the passphrase approves the calling session's device.
pub struct ApproveDevice {
    accounts: Arc<dyn Accounts>,
    sessions: Arc<dyn Sessions>,
    devices: Arc<dyn Devices>,
    keys: Arc<dyn HistoryKeys>,
    approvals: Arc<dyn DeviceApprovals>,
    verifier: Arc<dyn Ed25519Verifier>,
    notifier: Arc<dyn ApprovalNotifier>,
}

impl ApproveDevice {
    pub fn new(
        accounts: Arc<dyn Accounts>,
        sessions: Arc<dyn Sessions>,
        devices: Arc<dyn Devices>,
        keys: Arc<dyn HistoryKeys>,
        approvals: Arc<dyn DeviceApprovals>,
        verifier: Arc<dyn Ed25519Verifier>,
        notifier: Arc<dyn ApprovalNotifier>,
    ) -> Self {
        Self {
            accounts,
            sessions,
            devices,
            keys,
            approvals,
            verifier,
            notifier,
        }
    }

    /// The same approval again is a success; only a new one is announced.
    pub async fn execute(
        &self,
        bearer: &Bearer,
        approved: DeviceId,
        by: ApprovalBy,
        signature: Ed25519Signature,
    ) -> Result<(), KeyDirectoryError> {
        let owner = bearer.user;
        let account = self.accounts.find(owner).await?.ok_or_else(|| {
            KeyDirectoryError::Unexpected(anyhow::anyhow!("the approving account is gone"))
        })?;
        for _ in 0..ATTEMPTS {
            let signer = the_callers_device(&*self.sessions, &*self.devices, bearer).await?;
            let approved_device = self.devices.find(approved).await?;
            let current = match by {
                ApprovalBy::Passphrase(_) => self
                    .keys
                    .current(owner)
                    .await
                    .map_err(|e| KeyDirectoryError::Unexpected(e.into()))?
                    .map(|held| held.key),
                ApprovalBy::Device => None,
            };
            let facts = ApprovalFacts {
                actor: &account.actor_uri,
                signer: &signer,
                approved: approved_device.as_ref(),
                current: current.as_ref(),
            };
            let checked = may_approve(approved, by, signature.clone(), facts, &*self.verifier)?;
            match self.approvals.approve(owner, &checked).await? {
                Approve::Recorded => {
                    tracing::info!(user_id = %owner, device_id = %approved, approver = ?checked.approver(), "device approved");
                    self.notifier.device_approved(owner, approved);
                    return Ok(());
                }
                Approve::AlreadyHeld => return Ok(()),
                Approve::Stale => continue,
            }
        }
        Err(KeyDirectoryError::Unexpected(anyhow::anyhow!(
            "the devices kept changing while {approved} was approved"
        )))
    }
}

/// `POST /api/keys/devices/approval-requests`: the calling session's device asks the account's
/// other devices to approve it.
pub struct OpenApprovalRequest {
    sessions: Arc<dyn Sessions>,
    devices: Arc<dyn Devices>,
    requests: Arc<dyn ApprovalRequests>,
    notifier: Arc<dyn ApprovalNotifier>,
}

impl OpenApprovalRequest {
    pub fn new(
        sessions: Arc<dyn Sessions>,
        devices: Arc<dyn Devices>,
        requests: Arc<dyn ApprovalRequests>,
        notifier: Arc<dyn ApprovalNotifier>,
    ) -> Self {
        Self {
            sessions,
            devices,
            requests,
            notifier,
        }
    }

    pub async fn execute(
        &self,
        bearer: &Bearer,
        now: OffsetDateTime,
    ) -> Result<ApprovalRequest, KeyDirectoryError> {
        let device = the_callers_device(&*self.sessions, &*self.devices, bearer).await?;
        let request = ApprovalRequest::open_for(&device, now)?;
        let closed = match self.requests.open(&request).await? {
            Opened::Opened { closed } => closed,
            Opened::TooMany => return Err(RequestRefusal::TooMany.into()),
            Opened::Stale => {
                return Err(revoked_meanwhile(&*self.sessions, &*self.devices, bearer).await);
            }
        };
        let sessions = sessions_of(&*self.sessions, bearer.user).await?;
        for earlier in &closed {
            let to = earlier.parties().sessions(&sessions, now);
            self.notifier.approval_closed(bearer.user, &to, earlier.id);
        }
        let to = Audience::AllBut(vec![device.id]).sessions(&sessions, now);
        self.notifier
            .approval_requested(bearer.user, &to, &request, &device.label.name);
        Ok(request)
    }
}

/// An open request, and how its device is shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedRequest {
    pub request: ApprovalRequest,
    pub display_name: String,
}

/// `GET /api/keys/devices/approval-requests`: the account's open requests, for a device that
/// missed their push.
pub struct ListApprovalRequests {
    sessions: Arc<dyn Sessions>,
    devices: Arc<dyn Devices>,
    requests: Arc<dyn ApprovalRequests>,
}

impl ListApprovalRequests {
    pub fn new(
        sessions: Arc<dyn Sessions>,
        devices: Arc<dyn Devices>,
        requests: Arc<dyn ApprovalRequests>,
    ) -> Self {
        Self {
            sessions,
            devices,
            requests,
        }
    }

    pub async fn execute(
        &self,
        bearer: &Bearer,
        now: OffsetDateTime,
    ) -> Result<Vec<ListedRequest>, KeyDirectoryError> {
        the_callers_device(&*self.sessions, &*self.devices, bearer).await?;
        let open = self.requests.open_of(bearer.user, now).await?;
        let devices = self.devices.list(bearer.user).await?;
        Ok(open
            .into_iter()
            .map(|request| ListedRequest {
                display_name: devices
                    .iter()
                    .find(|device| device.id == request.device)
                    .map(|device| device.label.name.clone())
                    .unwrap_or_default(),
                request,
            })
            .collect())
    }
}

/// `POST /api/keys/devices/approval-requests/{id}/messages`: one handshake message, relayed to the
/// other side.
pub struct PostApprovalMessage {
    sessions: Arc<dyn Sessions>,
    devices: Arc<dyn Devices>,
    requests: Arc<dyn ApprovalRequests>,
    notifier: Arc<dyn ApprovalNotifier>,
}

impl PostApprovalMessage {
    pub fn new(
        sessions: Arc<dyn Sessions>,
        devices: Arc<dyn Devices>,
        requests: Arc<dyn ApprovalRequests>,
        notifier: Arc<dyn ApprovalNotifier>,
    ) -> Self {
        Self {
            sessions,
            devices,
            requests,
            notifier,
        }
    }

    pub async fn execute(
        &self,
        bearer: &Bearer,
        id: ApprovalRequestId,
        body: ApprovalMessageBody,
        now: OffsetDateTime,
    ) -> Result<MessageSeq, KeyDirectoryError> {
        let device = the_callers_device(&*self.sessions, &*self.devices, bearer).await?;
        let (request, seq, bound) = match self
            .requests
            .post(bearer.user, id, &device, &body, now)
            .await?
        {
            Post::Posted {
                request,
                seq,
                bound,
            } => (request, seq, bound),
            Post::Refused(refusal) => return Err(refusal.into()),
            Post::Stale => {
                return Err(revoked_meanwhile(&*self.sessions, &*self.devices, bearer).await);
            }
        };
        let sessions = sessions_of(&*self.sessions, bearer.user).await?;
        let to = request.counterpart(device.id).sessions(&sessions, now);
        self.notifier.approval_message(bearer.user, &to, id, seq);
        if bound {
            let to = request.bystanders().sessions(&sessions, now);
            self.notifier.approval_closed(bearer.user, &to, id);
        }
        Ok(seq)
    }
}

/// `GET /api/keys/devices/approval-requests/{id}/messages?after=`: what the other side posted.
pub struct ReadApprovalMessages {
    sessions: Arc<dyn Sessions>,
    devices: Arc<dyn Devices>,
    requests: Arc<dyn ApprovalRequests>,
}

impl ReadApprovalMessages {
    pub fn new(
        sessions: Arc<dyn Sessions>,
        devices: Arc<dyn Devices>,
        requests: Arc<dyn ApprovalRequests>,
    ) -> Self {
        Self {
            sessions,
            devices,
            requests,
        }
    }

    pub async fn execute(
        &self,
        bearer: &Bearer,
        id: ApprovalRequestId,
        after: MessageSeq,
        now: OffsetDateTime,
    ) -> Result<Vec<ApprovalMessage>, KeyDirectoryError> {
        let device = the_callers_device(&*self.sessions, &*self.devices, bearer).await?;
        match self
            .requests
            .read(bearer.user, id, device.id, after, now)
            .await?
        {
            Read::Messages(messages) => Ok(messages),
            Read::Refused(refusal) => Err(refusal.into()),
        }
    }
}

/// `DELETE /api/keys/devices/approval-requests/{id}`: either side ends the request — a wrong code
/// ends it on the device that found it wrong.
pub struct CloseApprovalRequest {
    sessions: Arc<dyn Sessions>,
    devices: Arc<dyn Devices>,
    requests: Arc<dyn ApprovalRequests>,
    notifier: Arc<dyn ApprovalNotifier>,
}

impl CloseApprovalRequest {
    pub fn new(
        sessions: Arc<dyn Sessions>,
        devices: Arc<dyn Devices>,
        requests: Arc<dyn ApprovalRequests>,
        notifier: Arc<dyn ApprovalNotifier>,
    ) -> Self {
        Self {
            sessions,
            devices,
            requests,
            notifier,
        }
    }

    pub async fn execute(
        &self,
        bearer: &Bearer,
        id: ApprovalRequestId,
        now: OffsetDateTime,
    ) -> Result<(), KeyDirectoryError> {
        let device = the_callers_device(&*self.sessions, &*self.devices, bearer).await?;
        let request = match self.requests.close(bearer.user, id, device.id, now).await? {
            Close::Closed(request) => request,
            Close::Refused(refusal) => return Err(refusal.into()),
        };
        let sessions = sessions_of(&*self.sessions, bearer.user).await?;
        let to = request.parties().sessions(&sessions, now);
        self.notifier.approval_closed(bearer.user, &to, id);
        Ok(())
    }
}

/// Deletes the requests that no longer count against their account's limit.
pub struct SweepApprovalRequests {
    requests: Arc<dyn ApprovalRequests>,
}

impl SweepApprovalRequests {
    pub fn new(requests: Arc<dyn ApprovalRequests>) -> Self {
        Self { requests }
    }

    pub async fn execute(&self, now: OffsetDateTime) -> Result<usize, KeyDirectoryError> {
        Ok(self
            .requests
            .delete_opened_before(window_start(now))
            .await?)
    }
}

#[cfg(test)]
mod tests;
