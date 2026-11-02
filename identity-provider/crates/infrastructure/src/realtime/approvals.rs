use std::sync::Arc;

use connections::Hub;
use domain::e2ee::{ApprovalNotifier, ApprovalRequest, MessageSeq};
use domain::{ApprovalRequestId, DeviceId, SessionId, UserId};
use uuid::Uuid;

use super::events::{
    ApprovalClosedPayload, ApprovalMessagePayload, ApprovalRequestedPayload, DeviceApprovedPayload,
    WsEvent,
};

/// Pushes approvals to the account's live sessions, and a request's news to the sessions of the
/// devices taking part; a device that missed one reads the device list, or the open requests, when
/// it connects.
pub struct HubApprovalNotifier {
    hub: Arc<Hub>,
}

impl HubApprovalNotifier {
    pub fn new(hub: Arc<Hub>) -> Self {
        Self { hub }
    }

    fn push_to(&self, owner: UserId, to: &[SessionId], event: WsEvent) {
        let sessions: Vec<Uuid> = to.iter().map(SessionId::as_uuid).collect();
        self.hub
            .send_to_sessions(&owner.as_uuid(), &sessions, super::frame(&event));
    }
}

impl ApprovalNotifier for HubApprovalNotifier {
    fn device_approved(&self, owner: UserId, device: DeviceId) {
        super::push(
            &self.hub,
            &owner.as_uuid(),
            WsEvent::DeviceApproved(DeviceApprovedPayload {
                device_id: device.as_uuid(),
            }),
        );
    }

    fn approval_requested(
        &self,
        owner: UserId,
        to: &[SessionId],
        request: &ApprovalRequest,
        display_name: &str,
    ) {
        self.push_to(
            owner,
            to,
            WsEvent::ApprovalRequested(ApprovalRequestedPayload {
                request_id: request.id.as_uuid(),
                device_id: request.device.as_uuid(),
                display_name: display_name.to_owned(),
            }),
        );
    }

    fn approval_message(
        &self,
        owner: UserId,
        to: &[SessionId],
        request: ApprovalRequestId,
        seq: MessageSeq,
    ) {
        self.push_to(
            owner,
            to,
            WsEvent::ApprovalMessage(ApprovalMessagePayload {
                request_id: request.as_uuid(),
                seq: seq.value(),
            }),
        );
    }

    fn approval_closed(&self, owner: UserId, to: &[SessionId], request: ApprovalRequestId) {
        self.push_to(
            owner,
            to,
            WsEvent::ApprovalClosed(ApprovalClosedPayload {
                request_id: request.as_uuid(),
            }),
        );
    }
}

#[cfg(test)]
mod tests;
