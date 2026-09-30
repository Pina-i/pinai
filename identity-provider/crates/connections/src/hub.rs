use std::sync::Arc;

use dashmap::DashMap;
use tokio::sync::mpsc;
use uuid::Uuid;

/// A text frame as it goes out: shared, not copied, between an account's connections.
pub type Frame = Arc<str>;

type ConnectionTx = mpsc::UnboundedSender<Frame>;

/// Handle returned when subscribing. Auto-unregisters from the hub on drop.
pub struct ConnectionHandle {
    conn_id: Uuid,
    user_id: Uuid,
    hub: Arc<Hub>,
}

impl ConnectionHandle {
    /// The unique connection ID for this WebSocket connection.
    pub fn conn_id(&self) -> Uuid {
        self.conn_id
    }
}

impl Drop for ConnectionHandle {
    fn drop(&mut self) {
        self.hub.remove(self.user_id, self.conn_id);
    }
}

/// In-memory registry of the live connections, keyed by user UUID.
///
/// Each user can have multiple connections (multi-device). Each connection
/// is identified by a unique `conn_id` for removal.
pub struct Hub {
    connections: DashMap<Uuid, Vec<(Uuid, ConnectionTx)>>,
}

impl Default for Hub {
    fn default() -> Self {
        Self::new()
    }
}

impl Hub {
    pub fn new() -> Self {
        Self {
            connections: DashMap::new(),
        }
    }

    /// Register a new connection for `user_id`.
    ///
    /// Returns the receiver half, a handle that auto-unregisters on drop, and
    /// `is_first` — true iff this connection was the user's first (i.e. the
    /// caller should publish an `online` presence event).
    ///
    /// `is_first` is decided under the same shard lock as the insert, so two
    /// concurrent subscribes for the same user can't both miss being marked
    /// first (the bug we'd otherwise hit when a web client double-mounts in
    /// React StrictMode and opens two WebSockets in the same tick).
    pub fn subscribe(
        self: &Arc<Self>,
        user_id: Uuid,
    ) -> (mpsc::UnboundedReceiver<Frame>, ConnectionHandle, bool) {
        let conn_id = Uuid::new_v4();
        let (tx, rx) = mpsc::unbounded_channel();

        let is_first = {
            let mut entry = self.connections.entry(user_id).or_default();
            entry.push((conn_id, tx));
            entry.len() == 1
        };

        let handle = ConnectionHandle {
            conn_id,
            user_id,
            hub: Arc::clone(self),
        };

        (rx, handle, is_first)
    }

    /// Send a frame to all connections for a given user.
    /// Dead senders are pruned automatically.
    pub fn send_to_user(&self, user_id: &Uuid, frame: Frame) {
        if let Some(mut senders) = self.connections.get_mut(user_id) {
            senders.retain(|(_, tx)| tx.send(Arc::clone(&frame)).is_ok());
            if senders.is_empty() {
                drop(senders);
                self.connections.remove(user_id);
            }
        }
    }

    /// Returns the number of active connections for a user.
    pub fn connection_count(&self, user_id: &Uuid) -> usize {
        self.connections
            .get(user_id)
            .map(|senders| senders.len())
            .unwrap_or(0)
    }

    fn remove(&self, user_id: Uuid, conn_id: Uuid) {
        if let Some(mut senders) = self.connections.get_mut(&user_id) {
            senders.retain(|(id, _)| *id != conn_id);
            if senders.is_empty() {
                drop(senders);
                self.connections.remove(&user_id);
            }
        }
    }
}

#[cfg(test)]
mod tests;
