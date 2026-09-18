//! S3-compatible object storage client for avatars and attachments.

mod client;
mod error;

pub use client::{StorageClient, StorageConfig};
pub use error::StorageError;
