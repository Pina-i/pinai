//! Timers and relays that drive the application, spawned by the composition root beside the
//! HTTP server. Each runs until `stop` is cancelled; a run under way finishes first.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use application::auth::SweepSignups;
use application::e2ee::{SweepKeyPackages, SweepWelcomes};
use application::messaging::{SweepOrphanAttachments, SweepStaleDeliveries};
use application::presence::{
    ApplyPresence, DeliverTyping, PollPeers, ReceivePeerSignal, SweepIdle,
};
use domain::identity::Domain;
use domain::presence::Signal;
use futures_core::stream::BoxStream;
use futures_util::StreamExt;
use time::OffsetDateTime;
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

#[cfg(test)]
mod tests;
