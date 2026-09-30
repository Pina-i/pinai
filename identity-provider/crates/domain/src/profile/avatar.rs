use bytes::Bytes;
use time::OffsetDateTime;

use crate::ValidationError;

/// The image formats an avatar may be in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ImageKind {
    Jpeg,
    Png,
    Webp,
    Gif,
}

impl ImageKind {
    pub const ALL: [Self; 4] = [Self::Jpeg, Self::Png, Self::Webp, Self::Gif];

    pub fn from_mime(mime: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.mime() == mime)
    }

    pub fn mime(self) -> &'static str {
        match self {
            Self::Jpeg => "image/jpeg",
            Self::Png => "image/png",
            Self::Webp => "image/webp",
            Self::Gif => "image/gif",
        }
    }
}

/// An uploaded avatar: an image of one of the kinds, 1 byte to 2 MiB.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvatarImage {
    kind: ImageKind,
    bytes: Bytes,
}

impl AvatarImage {
    pub const MAX_BYTES: usize = 2 * 1024 * 1024;

    /// `content_type` as the upload declared it.
    pub fn parse(content_type: Option<&str>, bytes: Bytes) -> Result<Self, ValidationError> {
        let refuse = |reason: &str| ValidationError::new("avatar", reason);
        let content_type = content_type.ok_or_else(|| refuse("Content-Type header is required"))?;
        let kind = ImageKind::from_mime(content_type).ok_or_else(|| {
            refuse("Content-Type must be image/jpeg, image/png, image/webp, or image/gif")
        })?;
        if bytes.is_empty() {
            return Err(refuse("Body cannot be empty"));
        }
        if bytes.len() > Self::MAX_BYTES {
            return Err(refuse("Avatar must be under 2 MiB"));
        }
        Ok(Self { kind, bytes })
    }

    pub fn kind(&self) -> ImageKind {
        self.kind
    }

    pub fn bytes(&self) -> &Bytes {
        &self.bytes
    }
}

/// The URL an upload is published at: where it is stored, versioned by the upload time. The
/// store keeps one object per account, so under an unchanged URL a browser — here or on a peer
/// — would keep showing the old image.
pub fn published_url(stored: &str, uploaded_at: OffsetDateTime) -> String {
    format!("{stored}?v={}", uploaded_at.unix_timestamp())
}

#[cfg(test)]
mod tests;
