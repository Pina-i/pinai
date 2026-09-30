//! The live connections of this instance's accounts, each a queue of frames to write. Shared by
//! the WebSocket's two adapters — `api` registers a connection and writes its frames out,
//! `infrastructure` pushes to an account's connections — and knowing nothing of what the frames
//! say: the wire format is theirs.

mod hub;

pub use hub::{ConnectionHandle, Frame, Hub};
