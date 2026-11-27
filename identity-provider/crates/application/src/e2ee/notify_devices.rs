use std::sync::Arc;

use domain::auth::Sessions;
use domain::e2ee::{
    ApprovalRequests, Delivery, DeviceApprovals, Happened, PushAlert, PushRegistrations,
    PushRelays, arrival_still_waits, push_recipients,
};
use time::OffsetDateTime;

/// Tells the account's approved devices, by a push notice, that a device asks a code, still waits
/// after arriving, or asks to start the history over: what their apps, closed, can't hear on the
/// WebSocket. Best effort — what fails is warned about, never with a token — and a registration
/// the relay no longer reaches is forgotten.
pub struct NotifyDevices {
    approvals: Arc<dyn DeviceApprovals>,
    requests: Arc<dyn ApprovalRequests>,
    sessions: Arc<dyn Sessions>,
    pushes: Arc<dyn PushRegistrations>,
    relays: Arc<dyn PushRelays>,
}

impl NotifyDevices {
    pub fn new(
        approvals: Arc<dyn DeviceApprovals>,
        requests: Arc<dyn ApprovalRequests>,
        sessions: Arc<dyn Sessions>,
        pushes: Arc<dyn PushRegistrations>,
        relays: Arc<dyn PushRelays>,
    ) -> Self {
        Self {
            approvals,
            requests,
            sessions,
            pushes,
            relays,
        }
    }

    pub async fn execute(&self, alert: PushAlert, now: OffsetDateTime) {
        if let Err(e) = self.tell(alert, now).await {
            tracing::warn!(error = ?e, user_id = %alert.owner, "a push notice went unsent");
        }
    }

    async fn tell(&self, alert: PushAlert, now: OffsetDateTime) -> anyhow::Result<()> {
        let held = self.pushes.held(alert.owner).await?;
        if held.is_empty() {
            return Ok(());
        }
        let trust = self.approvals.trust(alert.owner).await?;
        if alert.what == Happened::Arrived {
            let open = self.requests.open_of(alert.owner, now).await?;
            if !arrival_still_waits(&trust, alert.device, &open) {
                return Ok(());
            }
        }
        let sessions = self.sessions.of_user(alert.owner).await?;
        let notice = alert.notice();
        for (device, to) in push_recipients(&trust, &held, &sessions, alert.device, now) {
            match self.relays.send(to, notice).await {
                Ok(Delivery::Sent) => {}
                Ok(Delivery::Gone) => {
                    if let Err(e) = self.pushes.forget(alert.owner, *device, &to.token).await {
                        tracing::warn!(error = ?e, device_id = %device, "a push registration gone stays");
                    }
                }
                Err(e) => {
                    tracing::warn!(error = ?e, device_id = %device, "a push notice went unsent");
                }
            }
        }
        Ok(())
    }
}
