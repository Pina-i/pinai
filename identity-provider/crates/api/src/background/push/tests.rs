use std::sync::Mutex as StdMutex;

use domain::e2ee::testing::{RecordingDeviceNotifier, RecordingDeviceTrustNotifier};
use domain::e2ee::{HistoryGeneration, StartOverRequest};

use super::*;

fn at() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_788_000_000).unwrap()
}

fn alert(what: Happened) -> PushAlert {
    PushAlert {
        owner: UserId::generate(),
        device: DeviceId::generate(),
        what,
    }
}

#[tokio::test]
async fn the_notifiers_still_tell_the_sessions_and_queue_what_a_phone_should_hear() {
    let (alerts, mut queue) = push_alerts();
    let (devices, trust) = (
        Arc::new(RecordingDeviceNotifier::default()),
        Arc::new(RecordingDeviceTrustNotifier::default()),
    );
    let (telling_devices, telling_trust) = (
        alerts.telling_devices(devices.clone()),
        alerts.telling_trust(trust.clone()),
    );
    let (owner, laptop) = (UserId::generate(), DeviceId::generate());
    let actor = ActorUri::parse("https://idp.test/users/alice_t3st0").unwrap();
    let request = ApprovalRequest {
        id: ApprovalRequestId::generate(),
        owner,
        device: laptop,
        approver: None,
        created_at: at(),
        expires_at: at() + time::Duration::minutes(10),
        closed_at: None,
    };
    let start_over = StartOverRequest {
        id: StartOverRequestId::generate(),
        owner,
        device: laptop,
        generation: HistoryGeneration::FIRST,
        created_at: at(),
        ended: None,
    };

    telling_devices.device_joined(
        owner,
        &actor,
        laptop,
        &DeviceRootKey::parse(&[1; 32]).unwrap(),
    );
    telling_devices.key_packages_low(owner);
    telling_trust.approval_requested(owner, &[], &request, "Laptop");
    telling_trust.approval_closed(owner, &[], request.id);
    telling_trust.device_approved(owner, laptop);
    telling_trust.start_over_requested(owner, &[], &start_over, "Laptop", at());

    assert_eq!(devices.joined().len(), 1);
    assert_eq!(devices.key_packages_low(), vec![owner]);
    assert_eq!(trust.sent().len(), 4);
    let mut queued = Vec::new();
    while let Ok(alert) = queue.queue.try_recv() {
        queued.push((alert.owner, alert.device, alert.what));
    }
    assert_eq!(
        queued,
        vec![
            (owner, laptop, Happened::Arrived),
            (owner, laptop, Happened::AsksACode),
            (owner, laptop, Happened::AsksToStartOver),
        ]
    );
}

#[tokio::test]
async fn an_alert_past_what_the_queue_holds_is_dropped_never_waited_for() {
    let (alerts, mut queue) = push_alerts();

    for _ in 0..PUSH_ALERTS_QUEUED + 3 {
        alerts.submit(alert(Happened::AsksACode));
    }

    let mut waiting = 0;
    while queue.queue.try_recv().is_ok() {
        waiting += 1;
    }
    assert_eq!(waiting, PUSH_ALERTS_QUEUED);
}

#[tokio::test(start_paused = true)]
async fn an_arrival_is_handed_on_once_its_delay_is_past_the_others_at_once() {
    let (alerts, queue) = push_alerts();
    let told = Arc::new(StdMutex::new(Vec::new()));
    let stop = CancellationToken::new();
    let notify = {
        let told = Arc::clone(&told);
        move |alert: PushAlert| {
            let told = Arc::clone(&told);
            async move { told.lock().unwrap().push(alert.what) }
        }
    };
    let serving = tokio::spawn(serve_push_alerts(
        queue,
        notify,
        Duration::from_secs(120),
        stop.clone(),
    ));

    alerts.submit(alert(Happened::Arrived));
    alerts.submit(alert(Happened::AsksACode));
    alerts.submit(alert(Happened::AsksToStartOver));
    tokio::time::sleep(Duration::from_secs(119)).await;
    let before = told.lock().unwrap().clone();
    tokio::time::sleep(Duration::from_secs(2)).await;
    let after = told.lock().unwrap().clone();
    stop.cancel();
    serving.await.unwrap();

    assert_eq!(before, vec![Happened::AsksACode, Happened::AsksToStartOver]);
    assert_eq!(
        after,
        vec![
            Happened::AsksACode,
            Happened::AsksToStartOver,
            Happened::Arrived
        ]
    );
}

#[tokio::test(start_paused = true)]
async fn an_arrival_still_waiting_as_the_instance_stops_is_dropped() {
    let (alerts, queue) = push_alerts();
    let told = Arc::new(StdMutex::new(Vec::new()));
    let stop = CancellationToken::new();
    let notify = {
        let told = Arc::clone(&told);
        move |alert: PushAlert| {
            let told = Arc::clone(&told);
            async move { told.lock().unwrap().push(alert.what) }
        }
    };
    let serving = tokio::spawn(serve_push_alerts(
        queue,
        notify,
        Duration::from_secs(120),
        stop.clone(),
    ));

    alerts.submit(alert(Happened::Arrived));
    tokio::time::sleep(Duration::from_secs(1)).await;
    stop.cancel();
    serving.await.unwrap();
    tokio::time::sleep(Duration::from_secs(300)).await;

    assert!(told.lock().unwrap().is_empty());
}
