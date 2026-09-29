//! Timers that drive the application, spawned by the composition root beside the HTTP server.

use std::sync::Arc;
use std::time::Duration;

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

/// Every minute: fail the deliveries a dead process left `pending`. Runs for the process's life.
pub async fn sweep_stale_deliveries(sweep: Arc<SweepStaleDeliveries>) {
    let mut every = tokio::time::interval(Duration::from_secs(60));
    loop {
        every.tick().await;
        match sweep.execute(OffsetDateTime::now_utc()).await {
            Ok(0) => {}
            Ok(failed) => tracing::info!(failed, "stale deliveries swept"),
            Err(e) => tracing::warn!(error = ?e, "stale delivery sweep failed"),
        }
    }
}

/// Every five minutes: reap the uploads never sent. Runs for the process's life.
pub async fn sweep_orphan_attachments(sweep: Arc<SweepOrphanAttachments>) {
    let mut every = tokio::time::interval(Duration::from_secs(300));
    loop {
        every.tick().await;
        match sweep.execute(OffsetDateTime::now_utc()).await {
            Ok(0) => {}
            Ok(reaped) => tracing::info!(reaped, "orphan attachments reaped"),
            Err(e) => tracing::warn!(error = ?e, "orphan attachment sweep failed"),
        }
    }
}

/// Every five minutes: delete the KeyPackages expired or claimed past their grace. Runs for the
/// process's life.
pub async fn sweep_key_packages(sweep: Arc<SweepKeyPackages>) {
    let mut every = tokio::time::interval(Duration::from_secs(300));
    loop {
        every.tick().await;
        match sweep.execute(OffsetDateTime::now_utc()).await {
            Ok(0) => {}
            Ok(deleted) => tracing::info!(deleted, "spent key packages swept"),
            Err(e) => tracing::warn!(error = ?e, "key package sweep failed"),
        }
    }
}

/// Every five minutes: delete the Welcomes claimed past their grace. Runs for the process's life.
pub async fn sweep_welcomes(sweep: Arc<SweepWelcomes>) {
    let mut every = tokio::time::interval(Duration::from_secs(300));
    loop {
        every.tick().await;
        match sweep.execute(OffsetDateTime::now_utc()).await {
            Ok(0) => {}
            Ok(deleted) => tracing::info!(deleted, "claimed welcomes swept"),
            Err(e) => tracing::warn!(error = ?e, "welcome sweep failed"),
        }
    }
}

/// Every minute: the accounts idle for ten minutes go away. Runs for the process's life.
pub async fn sweep_idle_connections(sweep: Arc<SweepIdle>) {
    let mut every = tokio::time::interval(Duration::from_secs(60));
    loop {
        every.tick().await;
        match sweep.execute(OffsetDateTime::now_utc()).await {
            Ok(0) => {}
            Ok(away) => tracing::debug!(away, "idle accounts went away"),
            Err(e) => tracing::warn!(error = ?e, "idle sweep failed"),
        }
    }
}

/// The presence bus, to the accounts that may hear of each signal. A lost signal is acceptable:
/// presence reloads on connect and typing lasts three seconds.
pub async fn relay_signals(
    mut signals: BoxStream<'static, Signal>,
    apply: Arc<ApplyPresence>,
    deliver: Arc<DeliverTyping>,
) {
    while let Some(signal) = signals.next().await {
        let relayed = match &signal {
            Signal::Presence(event) => apply.execute(event).await,
            Signal::Typing(event) => deliver.execute(event).await,
        };
        if let Err(e) = relayed {
            tracing::warn!(error = ?e, "presence signal not relayed");
        }
    }
    tracing::warn!("presence bus closed");
}

/// Every 10 s: the remote friends' presence, from their instances. Runs for the process's life.
pub async fn poll_peers(poll: Arc<PollPeers>) {
    match poll.prime().await {
        Ok(friends) => tracing::info!(friends, "remote friends' presence polled"),
        Err(e) => tracing::warn!(error = ?e, "remote friends not loaded for presence polls"),
    }
    let mut every = tokio::time::interval(Duration::from_secs(10));
    loop {
        every.tick().await;
        let outcome = poll.execute(OffsetDateTime::now_utc()).await;
        for (peer, e) in outcome.failed {
            tracing::warn!(%peer, error = ?e, "presence poll failed");
        }
    }
}

/// What peers' streams carry, onto this instance's bus.
pub async fn relay_peer_signals(
    mut heard: BoxStream<'static, (Domain, Signal)>,
    receive: Arc<ReceivePeerSignal>,
) {
    while let Some((peer, signal)) = heard.next().await {
        if let Err(e) = receive.execute(&peer, &signal).await {
            tracing::warn!(error = ?e, "a peer's presence signal not relayed");
        }
    }
    tracing::warn!("peer presence streams closed");
}
