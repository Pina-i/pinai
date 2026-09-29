use std::fmt;

use time::OffsetDateTime;

use crate::{ConversationId, MessageId, ValidationError};

/// How many entries one upload holds at most.
pub const ARCHIVE_BATCH_CAP: usize = 50;

/// The AES-256-GCM nonce an entry was sealed with: 12 bytes, fresh per entry.
#[derive(Clone, PartialEq, Eq)]
pub struct ArchiveNonce([u8; 12]);

impl ArchiveNonce {
    pub fn parse(bytes: &[u8]) -> Result<Self, ValidationError> {
        bytes
            .try_into()
            .map(Self)
            .map_err(|_| ValidationError::new("nonce", "must be 12 bytes (AES-GCM)"))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for ArchiveNonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ArchiveNonce(..)")
    }
}

/// The per-user salt the History Archive Key is derived with, by Argon2id: 16 bytes, not
/// secret — it only slows an offline guess at a stolen archive.
#[derive(Clone, PartialEq, Eq)]
pub struct ArchiveSalt([u8; 16]);

impl ArchiveSalt {
    pub fn parse(bytes: &[u8]) -> Result<Self, ValidationError> {
        bytes
            .try_into()
            .map(Self)
            .map_err(|_| ValidationError::new("salt", "must be exactly 16 bytes"))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for ArchiveSalt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ArchiveSalt(..)")
    }
}

/// A decrypted message, sealed again under the History Archive Key: opaque here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewArchiveEntry {
    /// The message's id: an entry is archived once per account.
    pub id: MessageId,
    pub conversation: ConversationId,
    pub ciphertext: Vec<u8>,
    pub nonce: ArchiveNonce,
    pub client_message_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveEntry {
    pub id: MessageId,
    pub conversation: ConversationId,
    pub ciphertext: Vec<u8>,
    pub nonce: ArchiveNonce,
    pub client_message_id: Option<String>,
    pub created_at: OffsetDateTime,
}

impl ArchiveEntry {
    /// Where the next page starts.
    pub fn cursor(&self) -> ArchiveCursor {
        ArchiveCursor {
            created_at: self.created_at,
            id: self.id,
        }
    }
}

/// A position in an archive, newest first: the entries strictly older than it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArchiveCursor {
    pub created_at: OffsetDateTime,
    pub id: MessageId,
}

/// Why an upload is refused as a whole.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("batch size must be 1..={ARCHIVE_BATCH_CAP}")]
pub struct BatchSize;

/// An upload holds 1 to [`ARCHIVE_BATCH_CAP`] entries.
pub fn check_archive_batch(entries: usize) -> Result<(), BatchSize> {
    if entries == 0 || entries > ARCHIVE_BATCH_CAP {
        return Err(BatchSize);
    }
    Ok(())
}

/// A page's size: 100 unless asked, and always 1 to 500.
pub fn archive_page_size(requested: Option<i64>) -> usize {
    let size = requested.unwrap_or(100).clamp(1, 500);
    usize::try_from(size).unwrap_or(1)
}

#[cfg(test)]
mod tests;
