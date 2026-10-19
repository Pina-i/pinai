//! The live connections of this instance's accounts, each a queue of frames to write. Shared by
//! the WebSocket's two adapters — `api` registers a connection and writes its frames out,
//! `infrastructure` pushes to an account's connections — and knowing nothing of what the frames
//! say: the wire format is theirs. Each connection carries the session it was opened under, as an
//! opaque id, so that session ending closes it.

mod hub;

pub use hub::{ConnectionHandle, Frame, Hub};
