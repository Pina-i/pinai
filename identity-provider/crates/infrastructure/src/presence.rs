//! The instance's presence bus over Redis pub-sub, and the durable events a WebSocket replays.

mod wire;

use std::sync::Arc;

use crate::broker::RedisBroker;
use anyhow::Context;
use domain::UserId;
use domain::presence::{MissedEvent, MissedEvents, PresenceError, Signal, SignalBus, SignalFeed};
use futures_core::stream::BoxStream;

pub(crate) use wire::{decode_presence, decode_typing, encode as encode_json};

/// `presence:<domain>` and `typing:<conversation>`, in the JSON a peer's stream carries too.
pub struct RedisSignalBus {
    broker: Arc<RedisBroker>,
    domain: String,
}

impl RedisSignalBus {
    pub fn new(broker: Arc<RedisBroker>, domain: String) -> Self {
        Self { broker, domain }
    }
}

#[async_trait::async_trait]
impl SignalBus for RedisSignalBus {
    async fn publish(&self, signal: &Signal) -> Result<(), PresenceError> {
        let (channel, payload) = encode(&self.domain, signal)?;
        self.broker
            .publish_presence(&channel, &payload)
            .await
            .context("publish on the presence bus")?;
        Ok(())
    }
}

/// A signal's channel and JSON.
fn encode(domain: &str, signal: &Signal) -> Result<(String, String), PresenceError> {
    let channel = match signal {
        Signal::Presence(_) => format!("presence:{domain}"),
        Signal::Typing(event) => format!("typing:{}", event.conversation),
    };
    Ok((channel, encode_json(signal)?))
}

/// A message heard on a presence or typing channel; `None` for anything malformed.
fn decode(channel: &str, payload: &str) -> Option<Signal> {
    if channel.starts_with("presence:") {
        return decode_presence(payload);
    }
    if channel.starts_with("typing:") {
        return decode_typing(payload);
    }
    None
}

/// Every signal on the instance's bus, as a stream: this instance's own, and those a peer's
/// stream republished here.
pub async fn signals(redis_url: &str, domain: &str) -> anyhow::Result<BoxStream<'static, Signal>> {
    let presence = format!("presence:{domain}");
    let mut messages =
        crate::broker::subscribe_channels(redis_url, &[presence.as_str()], &["typing:*"])
            .await
            .context("subscribe to the presence bus")?;
    Ok(Box::pin(futures_util::stream::poll_fn(move |cx| {
        loop {
            match messages.poll_recv(cx) {
                std::task::Poll::Ready(Some(message)) => {
                    match decode(&message.channel, &message.payload) {
                        Some(signal) => return std::task::Poll::Ready(Some(signal)),
                        None => {
                            tracing::warn!(channel = %message.channel, "malformed presence signal")
                        }
                    }
                }
                other => return other.map(|_| None),
            }
        }
    })))
}

/// One subscription to the bus per listener: each peer's stream holds its own.
pub struct RedisSignalFeed {
    redis_url: String,
    domain: String,
}

impl RedisSignalFeed {
    pub fn new(redis_url: String, domain: String) -> Self {
        Self { redis_url, domain }
    }
}

#[async_trait::async_trait]
impl SignalFeed for RedisSignalFeed {
    async fn subscribe(&self) -> Result<BoxStream<'static, Signal>, PresenceError> {
        Ok(signals(&self.redis_url, &self.domain).await?)
    }
}

/// A user's durable event stream, which its WebSocket replays after a given event.
pub struct BrokerMissedEvents {
    broker: Arc<RedisBroker>,
}

impl BrokerMissedEvents {
    pub fn new(broker: Arc<RedisBroker>) -> Self {
        Self { broker }
    }
}

#[async_trait::async_trait]
impl MissedEvents for BrokerMissedEvents {
    async fn after(&self, user: UserId, last_id: &str) -> Result<Vec<MissedEvent>, PresenceError> {
        let entries = self
            .broker
            .read_after(user.as_uuid(), last_id)
            .await
            .context("read a user's missed events")?;
        Ok(entries
            .into_iter()
            .map(|entry| MissedEvent {
                id: entry.id,
                payload: entry.payload,
            })
            .collect())
    }
}

#[cfg(test)]
mod tests;
