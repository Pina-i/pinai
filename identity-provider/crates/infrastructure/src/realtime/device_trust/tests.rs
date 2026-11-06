use domain::e2ee::ApprovalRequest;
use serde_json::{Value, json};
use time::OffsetDateTime;

use super::*;

fn received(rx: &mut tokio::sync::mpsc::UnboundedReceiver<connections::Frame>) -> Option<Value> {
    rx.try_recv()
        .ok()
        .map(|frame| serde_json::from_str(&frame).unwrap())
}

#[test]
fn a_request_reaches_the_sessions_named_and_an_approval_the_whole_account() {
    let hub = Arc::new(Hub::new());
    let owner = UserId::generate();
    let (laptop_session, phone_session) = (SessionId::generate(), SessionId::generate());
    let (mut laptop, _laptop, _) = hub.subscribe(owner.as_uuid(), laptop_session.as_uuid());
    let (mut phone, _phone, _) = hub.subscribe(owner.as_uuid(), phone_session.as_uuid());
    let now = OffsetDateTime::now_utc();
    let request = ApprovalRequest {
        id: ApprovalRequestId::generate(),
        owner,
        device: DeviceId::generate(),
        approver: None,
        created_at: now,
        expires_at: now + time::Duration::minutes(10),
        closed_at: None,
    };
    let notifier = HubDeviceTrustNotifier::new(hub.clone());

    notifier.approval_requested(owner, &[phone_session], &request, "Chrome on Linux");
    let on_the_phone = received(&mut phone);
    let on_the_laptop = received(&mut laptop);
    notifier.device_approved(owner, request.device);

    assert_eq!(
        on_the_phone,
        Some(json!({
            "type": "approval_requested",
            "data": {
                "request_id": request.id.to_string(),
                "device_id": request.device.to_string(),
                "display_name": "Chrome on Linux",
            },
        }))
    );
    assert_eq!(on_the_laptop, None);
    let approved = json!({
        "type": "device_approved",
        "data": { "device_id": request.device.to_string() },
    });
    assert_eq!(received(&mut laptop), Some(approved.clone()));
    assert_eq!(received(&mut phone), Some(approved));
}

#[test]
fn a_message_and_an_end_carry_the_request_only() {
    let hub = Arc::new(Hub::new());
    let owner = UserId::generate();
    let session = SessionId::generate();
    let (mut socket, _handle, _) = hub.subscribe(owner.as_uuid(), session.as_uuid());
    let request = ApprovalRequestId::generate();
    let notifier = HubDeviceTrustNotifier::new(hub.clone());

    notifier.approval_message(owner, &[session], request, MessageSeq::parse(2).unwrap());
    notifier.approval_closed(owner, &[session], request);

    assert_eq!(
        received(&mut socket),
        Some(json!({
            "type": "approval_message",
            "data": { "request_id": request.to_string(), "seq": 2 },
        }))
    );
    assert_eq!(
        received(&mut socket),
        Some(json!({
            "type": "approval_closed",
            "data": { "request_id": request.to_string() },
        }))
    );
}

#[test]
fn a_share_is_announced_to_the_sessions_named_only() {
    let hub = Arc::new(Hub::new());
    let owner = UserId::generate();
    let (phones, laptops) = (SessionId::generate(), SessionId::generate());
    let (mut phone, _phone, _) = hub.subscribe(owner.as_uuid(), phones.as_uuid());
    let (mut laptop, _laptop, _) = hub.subscribe(owner.as_uuid(), laptops.as_uuid());
    let device = DeviceId::generate();
    let notifier = HubDeviceTrustNotifier::new(hub.clone());

    notifier.history_key_ready(owner, &[phones], device);

    assert_eq!(
        received(&mut phone),
        Some(json!({
            "type": "history_key_ready",
            "data": { "device_id": device.to_string() },
        }))
    );
    assert_eq!(received(&mut laptop), None);
}

#[test]
fn a_start_over_reaches_the_sessions_named_with_when_it_matures_and_its_end_the_request_only() {
    let hub = Arc::new(Hub::new());
    let owner = UserId::generate();
    let (laptops, freshs) = (SessionId::generate(), SessionId::generate());
    let (mut laptop, _laptop, _) = hub.subscribe(owner.as_uuid(), laptops.as_uuid());
    let (mut fresh, _fresh, _) = hub.subscribe(owner.as_uuid(), freshs.as_uuid());
    let at = OffsetDateTime::from_unix_timestamp(1_788_000_000).unwrap();
    let request = StartOverRequest {
        id: StartOverRequestId::generate(),
        owner,
        device: DeviceId::generate(),
        generation: domain::e2ee::HistoryGeneration::FIRST,
        created_at: at,
        ended: None,
    };
    let notifier = HubDeviceTrustNotifier::new(hub.clone());

    notifier.start_over_requested(
        owner,
        &[laptops],
        &request,
        "Chrome on Linux",
        at + time::Duration::days(7),
    );
    let on_the_fresh_device = received(&mut fresh);
    notifier.start_over_cancelled(owner, &[freshs], request.id, StartOverEnd::Cancelled);

    assert_eq!(
        received(&mut laptop),
        Some(json!({
            "type": "start_over_requested",
            "data": {
                "request_id": request.id.to_string(),
                "device_id": request.device.to_string(),
                "display_name": "Chrome on Linux",
                "ready_at": "2026-09-05T10:40:00Z",
            },
        }))
    );
    assert_eq!(on_the_fresh_device, None);
    assert_eq!(
        received(&mut fresh),
        Some(json!({
            "type": "start_over_cancelled",
            "data": { "request_id": request.id.to_string(), "reason": "cancelled" },
        }))
    );
    assert_eq!(received(&mut laptop), None);
}
