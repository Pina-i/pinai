use std::sync::Arc;

use dashmap::DashMap;
use tokio::sync::mpsc;
use uuid::Uuid;

use super::events::WsEvent;

type ConnectionTx = mpsc::UnboundedSender<WsEvent>;

/// Handle returned when subscribing. Auto-unregisters from the hub on drop.
pub struct ConnectionHandle {
    conn_id: Uuid,
    user_id: Uuid,
    hub: Arc<WsHub>,
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

/// In-memory registry of active WebSocket connections, keyed by user UUID.
///
/// Each user can have multiple connections (multi-device). Each connection
/// is identified by a unique `conn_id` for removal.
pub struct WsHub {
    connections: DashMap<Uuid, Vec<(Uuid, ConnectionTx)>>,
}

impl WsHub {
    pub fn new() -> Self {
        Self {
            connections: DashMap::new(),
        }
    }

    /// Register a new connection for `user_id`.
    /// Returns the receiver half and a handle that auto-unregisters on drop.
    pub fn subscribe(
        self: &Arc<Self>,
        user_id: Uuid,
    ) -> (mpsc::UnboundedReceiver<WsEvent>, ConnectionHandle) {
        let conn_id = Uuid::new_v4();
        let (tx, rx) = mpsc::unbounded_channel();

        self.connections
            .entry(user_id)
            .or_default()
            .push((conn_id, tx));

        let handle = ConnectionHandle {
            conn_id,
            user_id,
            hub: Arc::clone(self),
        };

        (rx, handle)
    }

    /// Send an event to all connections for a given user.
    /// Dead senders are pruned automatically.
    pub fn send_to_user(&self, user_id: &Uuid, event: WsEvent) {
        if let Some(mut senders) = self.connections.get_mut(user_id) {
            senders.retain(|(_, tx)| tx.send(event.clone()).is_ok());
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
