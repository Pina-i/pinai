use bytes::Bytes;
use futures_core::stream::BoxStream;

use crate::identity::ActorUri;
use crate::{AttachmentId, MessageId};

use super::Member;

/// An attachment as a message shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentView {
    pub id: AttachmentId,
    pub mime_type: String,
    pub byte_size: i64,
    pub original_filename: String,
}

/// An attachment as another instance's message describes it, before the limits vet it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OfferedAttachment {
    /// An ActivityPub `Document` — the only kind recorded.
    pub is_document: bool,
    pub url: Option<String>,
    pub media_type: Option<String>,
    pub name: Option<String>,
    pub size: Option<i64>,
}

/// An attachment recorded for a message another instance sent: its bytes stay there, at `url`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteAttachment {
    pub id: AttachmentId,
    pub url: String,
    pub mime_type: String,
    pub byte_size: i64,
    pub original_filename: String,
}

/// What this instance accepts on a message, uploaded here or delivered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentLimits {
    pub max_files: usize,
    pub max_bytes: i64,
    /// Lower-case MIME types.
    pub blocked_mimes: Vec<String>,
    /// Lower-case file extensions, without the dot. Uploads only: a delivered attachment's name
    /// is the sender's to obscure.
    pub blocked_extensions: Vec<String>,
}

/// Why an upload is refused. The texts are the API's.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UploadRefusal {
    #[error("no files in upload")]
    NoFiles,
    #[error("too many files (max {0} per request)")]
    TooManyFiles(usize),
    #[error("file extension '.{0}' is not allowed")]
    BlockedExtension(String),
    #[error("MIME type '{0}' is not allowed")]
    BlockedMime(String),
    #[error("file '{0}' is empty")]
    Empty(String),
    #[error("file '{filename}' exceeds max size of {max} bytes")]
    TooLarge { filename: String, max: i64 },
    #[error("`attachment_id` requires exactly one file in the request")]
    ChosenIdNeedsOneFile,
}

/// Whether `url` is `…/api/attachments/{id}/content` on the instance — scheme and domain — the
/// sender lives on.
fn is_content_endpoint_of(url: &str, sender: &ActorUri) -> bool {
    let Ok(uri) = ActorUri::parse(url) else {
        return false;
    };
    let id = uri
        .path()
        .strip_prefix("/api/attachments/")
        .and_then(|rest| rest.strip_suffix("/content"));
    uri.scheme() == sender.scheme()
        && uri.domain() == sender.domain()
        && id.is_some_and(|id| id.parse::<uuid::Uuid>().is_ok())
}

/// A file name's extension, lower-case; a leading dot starts a name, not an extension.
fn extension_of(filename: &str) -> Option<String> {
    let (stem, extension) = filename.rsplit_once('.')?;
    (!stem.is_empty() && !extension.is_empty()).then(|| extension.to_lowercase())
}

/// A file a user uploads, vetted by the limits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadFile {
    filename: String,
    mime_type: String,
    bytes: Vec<u8>,
}

impl UploadFile {
    /// The whole file, once `check_file` let its bytes be read.
    pub fn new(
        limits: &AttachmentLimits,
        filename: String,
        mime_type: String,
        bytes: Vec<u8>,
    ) -> Result<Self, UploadRefusal> {
        if bytes.is_empty() {
            return Err(UploadRefusal::Empty(filename));
        }
        if bytes.len() as u64 > limits.max_bytes.max(0) as u64 {
            return Err(UploadRefusal::TooLarge {
                filename,
                max: limits.max_bytes,
            });
        }
        Ok(Self {
            filename,
            mime_type,
            bytes,
        })
    }

    pub fn filename(&self) -> &str {
        &self.filename
    }

    pub fn mime_type(&self) -> &str {
        &self.mime_type
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// An attachment this instance holds: uploaded here (its bytes in our object store), or recorded
/// for a message another instance delivered (its bytes at `remote_url`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attachment {
    pub id: AttachmentId,
    pub uploader: ActorUri,
    /// `None` while it is an orphan: uploaded, not yet sent.
    pub message: Option<MessageId>,
    pub mime_type: String,
    pub byte_size: i64,
    pub original_filename: String,
    pub remote_url: Option<String>,
}

impl Attachment {
    pub fn view(&self) -> AttachmentView {
        AttachmentView {
            id: self.id,
            mime_type: self.mime_type.clone(),
            byte_size: self.byte_size,
            original_filename: self.original_filename.clone(),
        }
    }

    /// Who may open it: its uploader, and — once sent — the active members of the conversation it
    /// was sent in.
    pub fn readable_by(&self, caller: &ActorUri, conversation_members: &[Member]) -> bool {
        &self.uploader == caller
            || (self.message.is_some()
                && conversation_members.iter().any(|m| &m.actor_uri == caller))
    }
}

/// Which peer may fetch the bytes of an attachment uploaded here: an instance — scheme and
/// domain — that one of the conversation's active members lives on.
pub fn peer_may_fetch(members: &[Member], peer: &ActorUri) -> bool {
    members
        .iter()
        .any(|m| m.actor_uri.scheme() == peer.scheme() && m.actor_uri.domain() == peer.domain())
}

/// An attachment's bytes as they arrive, with the length the source announced.
pub struct ByteStream {
    pub length: Option<u64>,
    pub chunks: BoxStream<'static, std::io::Result<Bytes>>,
}

impl ByteStream {
    /// At most `max` bytes: past them the stream ends in an error, whatever the source says.
    pub fn limited_to(self, max: u64) -> Self {
        Self {
            // A source announcing more is about to be cut off: its length is no promise.
            length: self.length.filter(|n| *n <= max),
            chunks: Box::pin(Limited {
                chunks: self.chunks,
                remaining: max,
                exceeded: false,
            }),
        }
    }
}

struct Limited {
    chunks: BoxStream<'static, std::io::Result<Bytes>>,
    remaining: u64,
    exceeded: bool,
}

impl futures_core::Stream for Limited {
    type Item = std::io::Result<Bytes>;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        use std::task::Poll;
        let this = self.get_mut();
        if this.exceeded {
            return Poll::Ready(None);
        }
        match this.chunks.as_mut().poll_next(cx) {
            Poll::Ready(Some(Ok(chunk))) if chunk.len() as u64 > this.remaining => {
                this.exceeded = true;
                Poll::Ready(Some(Err(std::io::Error::other(
                    "more bytes than the attachment declared",
                ))))
            }
            Poll::Ready(Some(Ok(chunk))) => {
                this.remaining -= chunk.len() as u64;
                Poll::Ready(Some(Ok(chunk)))
            }
            other => other,
        }
    }
}

impl AttachmentLimits {
    /// Before a file's bytes are read: its extension and declared MIME type.
    pub fn check_file(&self, filename: &str, mime_type: &str) -> Result<(), UploadRefusal> {
        if let Some(extension) = extension_of(filename)
            && self.blocked_extensions.contains(&extension)
        {
            return Err(UploadRefusal::BlockedExtension(extension));
        }
        if self.blocked_mimes.contains(&mime_type.to_lowercase()) {
            return Err(UploadRefusal::BlockedMime(mime_type.to_owned()));
        }
        Ok(())
    }

    /// The `count`-th file of an upload.
    pub fn check_count(&self, count: usize) -> Result<(), UploadRefusal> {
        if count > self.max_files {
            return Err(UploadRefusal::TooManyFiles(self.max_files));
        }
        Ok(())
    }

    /// A whole upload: at least one file, and a chosen id only for a single one.
    pub fn check_batch(&self, files: usize, chosen_id: bool) -> Result<(), UploadRefusal> {
        if files == 0 {
            return Err(UploadRefusal::NoFiles);
        }
        // The id is bound into the file's encryption: it can name one file only.
        if chosen_id && files != 1 {
            return Err(UploadRefusal::ChosenIdNeedsOneFile);
        }
        Ok(())
    }

    /// Vet what another instance offers: only the first `max_files` are considered, and each is
    /// recorded, or refused with the reason.
    pub fn admit(
        &self,
        offers: &[OfferedAttachment],
        sender: &ActorUri,
    ) -> Vec<Result<RemoteAttachment, &'static str>> {
        offers
            .iter()
            .take(self.max_files)
            .map(|offer| self.admit_one(offer, sender))
            .collect()
    }

    fn admit_one(
        &self,
        offer: &OfferedAttachment,
        sender: &ActorUri,
    ) -> Result<RemoteAttachment, &'static str> {
        if !offer.is_document {
            return Err("not a Document");
        }
        let url = offer
            .url
            .as_deref()
            .filter(|u| !u.is_empty())
            .ok_or("no url")?;
        // The bytes are fetched as this instance: a URL anywhere else would have us fetch
        // whatever a peer points us at, private addresses included.
        if !is_content_endpoint_of(url, sender) {
            return Err("not the sender's instance's content endpoint");
        }
        let mime_type = offer
            .media_type
            .as_deref()
            .filter(|m| !m.is_empty())
            .ok_or("no mediaType")?;
        let byte_size = offer.size.ok_or("no size")?;
        if byte_size <= 0 || byte_size > self.max_bytes {
            return Err("size out of range");
        }
        if self.blocked_mimes.contains(&mime_type.to_lowercase()) {
            return Err("MIME type blocked");
        }
        Ok(RemoteAttachment {
            id: AttachmentId::of_content_url(url),
            url: url.to_owned(),
            mime_type: mime_type.to_owned(),
            byte_size,
            original_filename: offer.name.as_deref().unwrap_or("attachment").to_owned(),
        })
    }
}

// The sender keys each attachment's content key by its id inside the encrypted body, so the
// recipient's row must carry the sender's id, not a fresh one.
impl AttachmentId {
    /// The id a content URL `…/api/attachments/{id}/content` carries, or a fresh one.
    pub fn of_content_url(url: &str) -> Self {
        let path = url.strip_suffix("/content").unwrap_or(url);
        super::message::trailing_uuid(path).map_or_else(Self::generate, Self::from)
    }
}

#[cfg(test)]
mod tests;
