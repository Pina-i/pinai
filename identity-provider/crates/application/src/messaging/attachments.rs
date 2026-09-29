//! Attachments: uploads, opening one (a blob token), reading its bytes — from our object store or
//! from the instance that hosts it — serving a peer's fetch, and reaping orphans.

mod open_attachment;
mod read_blob;
mod serve_peer_content;
mod sweep_orphan_attachments;
#[cfg(test)]
mod tests;
mod upload_attachments;

pub use open_attachment::{OpenAttachment, OpenedAttachment};
pub use read_blob::ReadBlob;
pub use serve_peer_content::ServePeerContent;
pub use sweep_orphan_attachments::SweepOrphanAttachments;
pub use upload_attachments::UploadAttachments;

use domain::messaging::ByteStream;

/// An attachment's bytes, with how to present them.
pub struct Blob {
    pub mime_type: String,
    pub original_filename: String,
    pub bytes: ByteStream,
}
