//! Who is around, and who is typing: presence states and typing indicators, both ephemeral —
//! never persisted, losing one is always acceptable. See identity-provider/specs/04-presence.md.

mod board;
mod connections;
mod error;
mod peers;
mod ports;
mod state;
mod targets;
#[cfg(any(test, feature = "test-utils"))]
pub mod testing;

pub use board::PresenceBoard;
pub use connections::{AWAY_AFTER, ConnectionTracker};
pub use error::PresenceError;
pub use peers::{PeerFilter, remote_members_by_domain, speaks_for};
pub use ports::{
    MissedEvent, MissedEvents, PeerPresence, PeerStreams, PresenceAudience, PresenceNotifier,
    SignalBus, SignalFeed,
};
pub use state::{PresenceEvent, PresenceState, Signal, TypingEvent, may_type};
pub use targets::PollTargets;
