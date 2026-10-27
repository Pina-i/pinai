//! Timers and relays that drive the application, spawned by the composition root beside the
//! HTTP server. Each runs until `stop` is cancelled — the reset requests' worker, until the
//! server has answered its last request —; a run under way finishes first.

use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use application::auth::{RequestPasswordReset, SweepSignups};
use application::e2ee::{SweepKeyPackages, SweepWelcomes};
use application::messaging::{SweepOrphanAttachments, SweepStaleDeliveries};
use application::presence::{
    ApplyPresence, DeliverTyping, PollPeers, ReceivePeerSignal, SweepIdle,
};
use domain::auth::{AuthError, Email};
use domain::identity::Domain;
use domain::presence::Signal;
use futures_core::stream::BoxStream;
use futures_util::{FutureExt, StreamExt};
use time::OffsetDateTime;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// `tick` every `period`, the first at once, until `stop`.
async fn every<F, Run>(period: Duration, stop: CancellationToken, mut tick: F)
where
    F: FnMut() -> Run,
    Run: Future<Output = ()>,
{
    let mut timer = tokio::time::interval(period);
    loop {
        tokio::select! {
            () = stop.cancelled() => return,
            _ = timer.tick() => tick().await,
        }
    }
}

/// The next item of `stream`, or `None` once `stop` is cancelled.
async fn next<T>(stream: &mut BoxStream<'static, T>, stop: &CancellationToken) -> Option<T> {
    tokio::select! {
        () = stop.cancelled() => None,
        item = stream.next() => item,
    }
}

/// Every minute: fail the deliveries a dead process left `pending`.
pub async fn sweep_stale_deliveries(sweep: Arc<SweepStaleDeliveries>, stop: CancellationToken) {
    every(Duration::from_secs(60), stop, || async {
        match sweep.execute(OffsetDateTime::now_utc()).await {
            Ok(0) => {}
            Ok(failed) => tracing::info!(failed, "stale deliveries swept"),
            Err(e) => tracing::warn!(error = ?e, "stale delivery sweep failed"),
        }
    })
    .await
}

/// Every five minutes: reap the uploads never sent.
pub async fn sweep_orphan_attachments(sweep: Arc<SweepOrphanAttachments>, stop: CancellationToken) {
    every(Duration::from_secs(300), stop, || async {
        match sweep.execute(OffsetDateTime::now_utc()).await {
            Ok(0) => {}
            Ok(reaped) => tracing::info!(reaped, "orphan attachments reaped"),
            Err(e) => tracing::warn!(error = ?e, "orphan attachment sweep failed"),
        }
    })
    .await
}

/// Every five minutes: delete the KeyPackages expired or claimed past their grace.
pub async fn sweep_key_packages(sweep: Arc<SweepKeyPackages>, stop: CancellationToken) {
    every(Duration::from_secs(300), stop, || async {
        match sweep.execute(OffsetDateTime::now_utc()).await {
            Ok(0) => {}
            Ok(deleted) => tracing::info!(deleted, "spent key packages swept"),
            Err(e) => tracing::warn!(error = ?e, "key package sweep failed"),
        }
    })
    .await
}

/// Every five minutes: delete the Welcomes claimed past their grace.
pub async fn sweep_welcomes(sweep: Arc<SweepWelcomes>, stop: CancellationToken) {
    every(Duration::from_secs(300), stop, || async {
        match sweep.execute(OffsetDateTime::now_utc()).await {
            Ok(0) => {}
            Ok(deleted) => tracing::info!(deleted, "claimed welcomes swept"),
            Err(e) => tracing::warn!(error = ?e, "welcome sweep failed"),
        }
    })
    .await
}

/// Every hour: spent signup codes and login tickets, and the accounts never confirmed.
pub async fn sweep_signups(sweep: Arc<SweepSignups>, stop: CancellationToken) {
    every(Duration::from_secs(3600), stop, || async {
        match sweep.execute(OffsetDateTime::now_utc()).await {
            Ok(swept) => tracing::info!(
                codes = swept.codes,
                tickets = swept.tickets,
                accounts = swept.accounts,
                sessions = swept.sessions,
                refresh_tokens = swept.refresh_tokens,
                invitations = swept.invitations,
                password_resets = swept.password_resets,
                "signups swept"
            ),
            Err(e) => tracing::warn!(error = ?e, "signup sweep failed"),
        }
    })
    .await
}

/// Every minute: the accounts idle for ten minutes go away.
pub async fn sweep_idle_connections(sweep: Arc<SweepIdle>, stop: CancellationToken) {
    every(Duration::from_secs(60), stop, || async {
        match sweep.execute(OffsetDateTime::now_utc()).await {
            Ok(0) => {}
            Ok(away) => tracing::debug!(away, "idle accounts went away"),
            Err(e) => tracing::warn!(error = ?e, "idle sweep failed"),
        }
    })
    .await
}

/// The presence bus, to the accounts that may hear of each signal. A lost signal is acceptable:
/// presence reloads on connect and typing lasts three seconds.
pub async fn relay_signals(
    mut signals: BoxStream<'static, Signal>,
    apply: Arc<ApplyPresence>,
    deliver: Arc<DeliverTyping>,
    stop: CancellationToken,
) {
    while let Some(signal) = next(&mut signals, &stop).await {
        let relayed = match &signal {
            Signal::Presence(event) => apply.execute(event).await,
            Signal::Typing(event) => deliver.execute(event).await,
        };
        if let Err(e) = relayed {
            tracing::warn!(error = ?e, "presence signal not relayed");
        }
    }
    if !stop.is_cancelled() {
        tracing::warn!("presence bus closed");
    }
}

/// Every 10 s: the remote friends' presence, from their instances.
pub async fn poll_peers(poll: Arc<PollPeers>, stop: CancellationToken) {
    match poll.prime().await {
        Ok(friends) => tracing::info!(friends, "remote friends' presence polled"),
        Err(e) => tracing::warn!(error = ?e, "remote friends not loaded for presence polls"),
    }
    every(Duration::from_secs(10), stop, || async {
        let outcome = poll.execute(OffsetDateTime::now_utc()).await;
        for (peer, e) in outcome.failed {
            tracing::warn!(%peer, error = ?e, "presence poll failed");
        }
    })
    .await
}

/// What peers' streams carry, onto this instance's bus.
pub async fn relay_peer_signals(
    mut heard: BoxStream<'static, (Domain, Signal)>,
    receive: Arc<ReceivePeerSignal>,
    stop: CancellationToken,
) {
    while let Some((peer, signal)) = next(&mut heard, &stop).await {
        if let Err(e) = receive.execute(&peer, &signal).await {
            tracing::warn!(error = ?e, "a peer's presence signal not relayed");
        }
    }
    if !stop.is_cancelled() {
        tracing::warn!("peer presence streams closed");
    }
}

/// How many reset requests wait at most; past it, one is dropped.
const RESET_REQUESTS_QUEUED: usize = 256;
/// What is warned about by count — requests dropped, mails the budget refused — is warned about
/// at most this often: a flood is one event, not a line each.
const WARNED_EVERY: Duration = Duration::from_secs(60);

/// Events warned about by their count, at most once every [`WARNED_EVERY`].
#[derive(Default)]
struct Tally {
    pending: usize,
    warned_at: Option<Instant>,
}

impl Tally {
    /// One more: the count to warn about now, if it is time.
    fn add(&mut self, now: Instant) -> Option<usize> {
        self.pending += 1;
        self.due(now)
    }

    /// The count not warned about yet, if it is time.
    fn due(&mut self, now: Instant) -> Option<usize> {
        if self.pending == 0
            || self
                .warned_at
                .is_some_and(|at| now.duration_since(at) < WARNED_EVERY)
        {
            return None;
        }
        self.warned_at = Some(now);
        Some(std::mem::take(&mut self.pending))
    }
}

/// The addresses `POST /forgot-password` took, on their way to [`serve_reset_requests`]: the
/// form is answered before — and whatever — the lookup and the mail, so neither its words nor its
/// timing tell whether an address has an account.
#[derive(Clone)]
pub struct ResetRequests {
    queue: mpsc::Sender<Email>,
    drops: Arc<Mutex<Tally>>,
}

/// What [`serve_reset_requests`] reads, and the drops it writes out the count of.
pub struct ResetRequestQueue {
    queue: mpsc::Receiver<Email>,
    drops: Arc<Mutex<Tally>>,
}

pub fn reset_requests() -> (ResetRequests, ResetRequestQueue) {
    let (sender, receiver) = mpsc::channel(RESET_REQUESTS_QUEUED);
    let drops = Arc::default();
    let requests = ResetRequests {
        queue: sender,
        drops: Arc::clone(&drops),
    };
    (
        requests,
        ResetRequestQueue {
            queue: receiver,
            drops,
        },
    )
}

impl ResetRequests {
    /// Never waits. A request dropped — the queue full, or no worker left — costs a mail asked
    /// for again, and is answered as any other.
    pub(crate) fn submit(&self, address: Email) {
        let Err(dropped) = self.queue.try_send(address) else {
            return;
        };
        let why = match dropped {
            mpsc::error::TrySendError::Full(_) => "too many waiting",
            mpsc::error::TrySendError::Closed(_) => "no worker is taking them",
        };
        if let Some(dropped) = self.drops.lock().unwrap().add(Instant::now()) {
            tracing::warn!(why, dropped, "reset link requests dropped");
        }
    }
}

#[cfg(test)]
impl ResetRequestQueue {
    /// The requests waiting now, one after the other, without waiting for more.
    pub(crate) async fn drain(&mut self, request: &RequestPasswordReset) {
        while let Ok(address) = self.queue.try_recv() {
            handle_reset_request(request, &address).await;
        }
    }
}

/// What came of a request, as far as the log is concerned.
enum Handled {
    Done,
    /// The instance's mail budget refused its mail: counted, not warned about one by one.
    OverBudget,
}

async fn handle_reset_request(request: &RequestPasswordReset, address: &Email) -> Handled {
    let handled = AssertUnwindSafe(request.execute(address, OffsetDateTime::now_utc()))
        .catch_unwind()
        .await;
    // These lines never hold the address. A panic's own message is the panic hook's to print.
    match handled {
        Ok(Ok(())) => {}
        Ok(Err(AuthError::MailBudgetSpent)) => return Handled::OverBudget,
        Ok(Err(e)) => tracing::warn!(error = ?e, "a reset link request failed"),
        Err(_) => tracing::error!("a reset link request panicked"),
    }
    Handled::Done
}

/// The reset links asked for, one request at a time, until `served` — the HTTP server has
/// answered its last request —; then those still waiting, until `out_of_time`: the instance's
/// ten seconds to stop, which the HTTP server's drain shares, the request under way included.
pub async fn serve_reset_requests(
    mut queue: ResetRequestQueue,
    request: Arc<RequestPasswordReset>,
    served: CancellationToken,
    out_of_time: CancellationToken,
) {
    let unsent = take_reset_requests(&mut queue, &request, &served, &out_of_time).await;
    if unsent > 0 {
        tracing::warn!(
            unsent,
            "reset link requests left unsent as the instance stopped"
        );
    }
}

/// How many requests were left unsent: waiting, or under way, when `out_of_time` came.
async fn take_reset_requests(
    queue: &mut ResetRequestQueue,
    request: &RequestPasswordReset,
    served: &CancellationToken,
    out_of_time: &CancellationToken,
) -> usize {
    let under_way = AtomicBool::new(false);
    let over_budget = Mutex::new(Tally::default());
    let take = async |address: Email| {
        under_way.store(true, Ordering::Relaxed);
        if let Handled::OverBudget = handle_reset_request(request, &address).await
            && let Some(refused) = over_budget.lock().unwrap().add(Instant::now())
        {
            tracing::warn!(
                refused,
                "reset links not mailed: the instance's mail budget is spent"
            );
        }
        under_way.store(false, Ordering::Relaxed);
    };
    let write_out = || {
        let now = Instant::now();
        if let Some(dropped) = queue.drops.lock().unwrap().due(now) {
            tracing::warn!(
                why = "too many waiting",
                dropped,
                "reset link requests dropped"
            );
        }
        if let Some(refused) = over_budget.lock().unwrap().due(now) {
            tracing::warn!(
                refused,
                "reset links not mailed: the instance's mail budget is spent"
            );
        }
    };
    let mut tick =
        tokio::time::interval_at(tokio::time::Instant::now() + WARNED_EVERY, WARNED_EVERY);
    let work = async {
        loop {
            tokio::select! {
                biased;
                () = served.cancelled() => break,
                next = queue.queue.recv() => match next {
                    Some(address) => take(address).await,
                    None => return,
                },
                _ = tick.tick() => write_out(),
            }
        }
        while let Ok(address) = queue.queue.try_recv() {
            take(address).await;
        }
    };
    let cut = tokio::select! {
        biased;
        () = work => false,
        () = out_of_time.cancelled() => true,
    };
    if !cut {
        return 0;
    }
    queue.queue.len() + usize::from(under_way.load(Ordering::Relaxed))
}

#[cfg(test)]
mod tests;
