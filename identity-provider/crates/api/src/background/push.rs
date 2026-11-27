//! The push notices' alerts: queued by the notifiers as they tell the live sessions, sent by
//! [`serve_push_alerts`] — see identity-provider/specs/push.md.

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use domain::e2ee::{
    ApprovalRequest, DeviceNotifier, DeviceRootKey, DeviceTrustNotifier, Happened, MessageSeq,
    PushAlert, StartOverEnd, StartOverRequest,
};
use domain::identity::ActorUri;
use domain::{ApprovalRequestId, DeviceId, SessionId, StartOverRequestId, UserId};
use time::OffsetDateTime;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use super::{Tally, WARNED_EVERY};

/// How many alerts wait at most to be taken; past it, one is dropped.
const PUSH_ALERTS_QUEUED: usize = 256;
/// How many are under way at most — arrivals waiting out their delay included; past it, one taken
/// is dropped.
const PUSH_ALERTS_UNDER_WAY: usize = 1024;

/// Where the notifiers put what the approved devices should hear of by a push notice. Never waits:
/// an alert dropped costs a notice, and the WebSocket push it came with went all the same.
#[derive(Clone)]
pub struct PushAlerts {
    queue: mpsc::Sender<PushAlert>,
    drops: Arc<Mutex<Tally>>,
}

/// What [`serve_push_alerts`] takes them from.
pub struct PushAlertQueue {
    queue: mpsc::Receiver<PushAlert>,
    drops: Arc<Mutex<Tally>>,
}

pub fn push_alerts() -> (PushAlerts, PushAlertQueue) {
    let (sender, receiver) = mpsc::channel(PUSH_ALERTS_QUEUED);
    let drops = Arc::default();
    (
        PushAlerts {
            queue: sender,
            drops: Arc::clone(&drops),
        },
        PushAlertQueue {
            queue: receiver,
            drops,
        },
    )
}

impl PushAlerts {
    fn submit(&self, alert: PushAlert) {
        if self.queue.try_send(alert).is_err() {
            dropped(&self.drops);
        }
    }

    /// `inner`, a device's first registration queued as its arrival too.
    pub fn telling_devices(&self, inner: Arc<dyn DeviceNotifier>) -> AlertingDeviceNotifier {
        AlertingDeviceNotifier {
            inner,
            alerts: self.clone(),
        }
    }

    /// `inner`, an approval request and a start over request queued too.
    pub fn telling_trust(&self, inner: Arc<dyn DeviceTrustNotifier>) -> AlertingTrustNotifier {
        AlertingTrustNotifier {
            inner,
            alerts: self.clone(),
        }
    }
}

fn dropped(drops: &Mutex<Tally>) {
    if let Some(dropped) = drops.lock().unwrap().add(Instant::now()) {
        tracing::warn!(dropped, "push alerts dropped: too many waiting");
    }
}

pub struct AlertingDeviceNotifier {
    inner: Arc<dyn DeviceNotifier>,
    alerts: PushAlerts,
}

impl DeviceNotifier for AlertingDeviceNotifier {
    fn device_joined(
        &self,
        owner: UserId,
        actor: &ActorUri,
        device: DeviceId,
        key: &DeviceRootKey,
    ) {
        self.inner.device_joined(owner, actor, device, key);
        self.alerts.submit(PushAlert {
            owner,
            device,
            what: Happened::Arrived,
        });
    }

    fn key_packages_low(&self, owner: UserId) {
        self.inner.key_packages_low(owner);
    }
}

pub struct AlertingTrustNotifier {
    inner: Arc<dyn DeviceTrustNotifier>,
    alerts: PushAlerts,
}

impl DeviceTrustNotifier for AlertingTrustNotifier {
    fn device_approved(&self, owner: UserId, device: DeviceId) {
        self.inner.device_approved(owner, device);
    }

    fn approval_requested(
        &self,
        owner: UserId,
        to: &[SessionId],
        request: &ApprovalRequest,
        display_name: &str,
    ) {
        self.inner
            .approval_requested(owner, to, request, display_name);
        self.alerts.submit(PushAlert {
            owner,
            device: request.device,
            what: Happened::AsksACode,
        });
    }

    fn approval_message(
        &self,
        owner: UserId,
        to: &[SessionId],
        request: ApprovalRequestId,
        seq: MessageSeq,
    ) {
        self.inner.approval_message(owner, to, request, seq);
    }

    fn approval_closed(&self, owner: UserId, to: &[SessionId], request: ApprovalRequestId) {
        self.inner.approval_closed(owner, to, request);
    }

    fn history_key_ready(&self, owner: UserId, to: &[SessionId], device: DeviceId) {
        self.inner.history_key_ready(owner, to, device);
    }

    fn start_over_requested(
        &self,
        owner: UserId,
        to: &[SessionId],
        request: &StartOverRequest,
        display_name: &str,
        ready_at: OffsetDateTime,
    ) {
        self.inner
            .start_over_requested(owner, to, request, display_name, ready_at);
        self.alerts.submit(PushAlert {
            owner,
            device: request.device,
            what: Happened::AsksToStartOver,
        });
    }

    fn start_over_cancelled(
        &self,
        owner: UserId,
        to: &[SessionId],
        request: StartOverRequestId,
        reason: StartOverEnd,
    ) {
        self.inner.start_over_cancelled(owner, to, request, reason);
    }
}

/// Takes the alerts as they come and hands each to `notify` — an arrival once `arrival_delay` is
/// past, so a device approved meanwhile is told of no more —, until `stop`. Best effort: what
/// waits or is under way then is dropped with the instance.
pub async fn serve_push_alerts<Notify, Told>(
    mut queue: PushAlertQueue,
    notify: Notify,
    arrival_delay: Duration,
    stop: CancellationToken,
) where
    Notify: Fn(PushAlert) -> Told,
    Told: Future<Output = ()> + Send + 'static,
{
    let mut under_way = JoinSet::new();
    let mut tick =
        tokio::time::interval_at(tokio::time::Instant::now() + WARNED_EVERY, WARNED_EVERY);
    loop {
        tokio::select! {
            biased;
            () = stop.cancelled() => break,
            next = queue.queue.recv() => match next {
                Some(_) if under_way.len() >= PUSH_ALERTS_UNDER_WAY => dropped(&queue.drops),
                Some(alert) => {
                    let wait = match alert.what {
                        Happened::Arrived => arrival_delay,
                        Happened::AsksACode | Happened::AsksToStartOver => Duration::ZERO,
                    };
                    let told = notify(alert);
                    under_way.spawn(async move {
                        tokio::time::sleep(wait).await;
                        told.await;
                    });
                }
                None => break,
            },
            Some(_) = under_way.join_next(), if !under_way.is_empty() => {}
            _ = tick.tick() => {
                if let Some(dropped) = queue.drops.lock().unwrap().due(Instant::now()) {
                    tracing::warn!(dropped, "push alerts dropped: too many waiting");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
