//! A device the account's devices haven't approved asks to start the history over; the approved
//! devices hear of it and may cancel it, and it matures once none of them is used for a week —
//! identity-provider/specs/e2ee.md § 3.12.

use std::sync::Arc;

use domain::StartOverRequestId;
use domain::auth::Sessions;
use domain::e2ee::{
    ApprovalRequired, Audience, DeviceApprovals, DeviceTrust, DeviceTrustNotifier, Devices,
    KeyDirectoryError, StartOverEnded, StartOverOpened, StartOverRefusal, StartOverRequest,
    StartOverRequests, start_over_sweep_before,
};
use domain::identity::Bearer;
use time::OffsetDateTime;

use super::approval::{ATTEMPTS, sessions_of, the_callers_device};

/// Tells the request's devices it ended without being used, and how: the asker, and the approved
/// devices whose prompt goes. The write is done, so a failure here is only logged.
pub(super) async fn tell_start_over_ended(
    sessions: &dyn Sessions,
    notifier: &dyn DeviceTrustNotifier,
    trust: &DeviceTrust,
    request: &StartOverRequest,
    now: OffsetDateTime,
) {
    match sessions.of_user(request.owner).await {
        Ok(held) => {
            let Some(ended) = request.ended else {
                return;
            };
            let to = request.audience(trust).sessions(&held, now);
            notifier.start_over_cancelled(request.owner, &to, request.id, ended.how);
        }
        Err(e) => {
            tracing::warn!(error = ?e, user_id = %request.owner, "the start over request's end went untold");
        }
    }
}

/// What asking comes to: the request, when it matures as of now, and whether it was opened now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartOverAsked {
    pub request: StartOverRequest,
    pub ready_at: OffsetDateTime,
    pub opened: bool,
}

/// `POST /api/history/start-over`: the calling session's device, not approved, asks to set the
/// account's next generation.
pub struct AskToStartOver {
    sessions: Arc<dyn Sessions>,
    devices: Arc<dyn Devices>,
    approvals: Arc<dyn DeviceApprovals>,
    start_overs: Arc<dyn StartOverRequests>,
    notifier: Arc<dyn DeviceTrustNotifier>,
}

impl AskToStartOver {
    pub fn new(
        sessions: Arc<dyn Sessions>,
        devices: Arc<dyn Devices>,
        approvals: Arc<dyn DeviceApprovals>,
        start_overs: Arc<dyn StartOverRequests>,
        notifier: Arc<dyn DeviceTrustNotifier>,
    ) -> Self {
        Self {
            sessions,
            devices,
            approvals,
            start_overs,
            notifier,
        }
    }

    /// Asking again while its request is open answers that one, and tells nobody again.
    pub async fn execute(
        &self,
        bearer: &Bearer,
        now: OffsetDateTime,
    ) -> Result<StartOverAsked, KeyDirectoryError> {
        let owner = bearer.user;
        for _ in 0..ATTEMPTS {
            let device = the_callers_device(&*self.sessions, &*self.devices, bearer).await?;
            let trust = self.approvals.trust(owner).await?;
            let request = StartOverRequest::open_for(&device, &trust, now)?;
            let (request, opened) = match self.start_overs.open(&request).await? {
                StartOverOpened::Opened(stored) => (stored, true),
                StartOverOpened::Existing(existing) => (existing, false),
                StartOverOpened::Refused(refusal) => return Err(refusal.into()),
                // Revoked, or a new generation set, since the reads: read again.
                StartOverOpened::Stale => continue,
            };
            let sessions = sessions_of(&*self.sessions, owner).await?;
            let ready_at = request.ready_at(&trust, &sessions);
            if opened {
                tracing::info!(user_id = %owner, device_id = %device.id, request_id = %request.id, "start over requested");
                let approved = Audience::Devices(trust.approved_under(request.generation));
                self.notifier.start_over_requested(
                    owner,
                    &approved.sessions(&sessions, now),
                    &request,
                    &device.label.name,
                    ready_at,
                );
            }
            return Ok(StartOverAsked {
                request,
                ready_at,
                opened,
            });
        }
        Err(KeyDirectoryError::Unexpected(anyhow::anyhow!(
            "the devices kept changing while a start over was asked"
        )))
    }
}

/// A request as its devices see it: the account's open one, or the asking device's latest, ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingStartOver {
    pub request: StartOverRequest,
    /// How the asking device is shown.
    pub display_name: String,
    /// When it matures, as of the last uses read now.
    pub ready_at: OffsetDateTime,
}

/// `GET /api/history/start-over`: the account's open request, for the device asking and the
/// approved devices that may cancel it; else the caller's own latest, ended, until it is swept —
/// so the device asking learns how it ended after a reload.
pub struct LoadStartOver {
    sessions: Arc<dyn Sessions>,
    devices: Arc<dyn Devices>,
    approvals: Arc<dyn DeviceApprovals>,
    start_overs: Arc<dyn StartOverRequests>,
}

impl LoadStartOver {
    pub fn new(
        sessions: Arc<dyn Sessions>,
        devices: Arc<dyn Devices>,
        approvals: Arc<dyn DeviceApprovals>,
        start_overs: Arc<dyn StartOverRequests>,
    ) -> Self {
        Self {
            sessions,
            devices,
            approvals,
            start_overs,
        }
    }

    pub async fn execute(&self, bearer: &Bearer) -> Result<PendingStartOver, KeyDirectoryError> {
        let owner = bearer.user;
        let device = the_callers_device(&*self.sessions, &*self.devices, bearer).await?;
        let trust = self.approvals.trust(owner).await?;
        let open = self.start_overs.open_of(owner).await?;
        let request = match open {
            Some(open) if open.may_read(device.id, &trust).is_ok() => open,
            open => match self.start_overs.latest_of(owner, device.id).await? {
                Some(mine) => mine,
                None if open.is_some() => return Err(ApprovalRequired.into()),
                None => return Err(StartOverRefusal::NotFound.into()),
            },
        };
        let sessions = sessions_of(&*self.sessions, owner).await?;
        Ok(PendingStartOver {
            ready_at: request.ready_at(&trust, &sessions),
            display_name: trust
                .device(request.device)
                .map(|asking| asking.label.name.clone())
                .unwrap_or_default(),
            request,
        })
    }
}

/// `DELETE /api/history/start-over/{id}`: an approved device cancels the request, or its device
/// withdraws it.
pub struct EndStartOver {
    sessions: Arc<dyn Sessions>,
    devices: Arc<dyn Devices>,
    approvals: Arc<dyn DeviceApprovals>,
    start_overs: Arc<dyn StartOverRequests>,
    notifier: Arc<dyn DeviceTrustNotifier>,
}

impl EndStartOver {
    pub fn new(
        sessions: Arc<dyn Sessions>,
        devices: Arc<dyn Devices>,
        approvals: Arc<dyn DeviceApprovals>,
        start_overs: Arc<dyn StartOverRequests>,
        notifier: Arc<dyn DeviceTrustNotifier>,
    ) -> Self {
        Self {
            sessions,
            devices,
            approvals,
            start_overs,
            notifier,
        }
    }

    pub async fn execute(
        &self,
        bearer: &Bearer,
        id: StartOverRequestId,
        now: OffsetDateTime,
    ) -> Result<(), KeyDirectoryError> {
        let owner = bearer.user;
        for _ in 0..ATTEMPTS {
            let device = the_callers_device(&*self.sessions, &*self.devices, bearer).await?;
            let request = self
                .start_overs
                .request(owner, id)
                .await?
                .ok_or(StartOverRefusal::NotFound)?;
            let trust = self.approvals.trust(owner).await?;
            let how = request.may_end(device.id, &trust)?;
            let ended = match self.start_overs.end(owner, id, device.id, how, now).await? {
                StartOverEnded::Ended(ended) => ended,
                StartOverEnded::Refused(refusal) => return Err(refusal.into()),
                // Revoked, or no longer approved, since the reads: decide again.
                StartOverEnded::Stale => continue,
            };
            tracing::info!(user_id = %owner, by = %device.id, request_id = %id, how = how.as_str(), "start over request ended");
            tell_start_over_ended(&*self.sessions, &*self.notifier, &trust, &ended, now).await;
            return Ok(());
        }
        Err(KeyDirectoryError::Unexpected(anyhow::anyhow!(
            "the devices kept changing while start over {id} ended"
        )))
    }
}

/// Deletes the requests that ended and no longer count against their account's limit.
pub struct SweepStartOverRequests {
    start_overs: Arc<dyn StartOverRequests>,
}

impl SweepStartOverRequests {
    pub fn new(start_overs: Arc<dyn StartOverRequests>) -> Self {
        Self { start_overs }
    }

    pub async fn execute(&self, now: OffsetDateTime) -> Result<usize, KeyDirectoryError> {
        Ok(self
            .start_overs
            .delete_ended_before(start_over_sweep_before(now))
            .await?)
    }
}

#[cfg(test)]
mod tests;
