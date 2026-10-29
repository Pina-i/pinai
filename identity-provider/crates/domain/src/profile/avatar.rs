use std::fmt;

use bytes::Bytes;
use time::OffsetDateTime;

use crate::identity::InstanceOrigin;
use crate::{UserId, ValidationError};

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

    /// What its file name ends with.
    pub fn extension(self) -> &'static str {
        match self {
            Self::Jpeg => "jpg",
            Self::Png => "png",
            Self::Webp => "webp",
            Self::Gif => "gif",
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

/// What an avatar's URL path starts with, its file name following.
pub const AVATARS_PATH_PREFIX: &str = "/avatars/";

/// An avatar's file name, `{user_id}.{ext}`: the last segment of its URL, and its key in the
/// store, one per account and kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AvatarFile {
    pub user: UserId,
    pub kind: ImageKind,
}

impl AvatarFile {
    /// Only the name it is written as — the id lowercase and hyphenated — so that one image
    /// has one URL.
    pub fn parse(name: &str) -> Option<Self> {
        let (id, extension) = name.rsplit_once('.')?;
        let kind = ImageKind::ALL
            .into_iter()
            .find(|kind| kind.extension() == extension)?;
        let user = UserId::from(uuid::Uuid::parse_str(id).ok()?);
        let file = Self { user, kind };
        (file.to_string() == name).then_some(file)
    }
}

impl fmt::Display for AvatarFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.user, self.kind.extension())
    }
}

/// Where this instance serves an account's image of `kind`.
pub fn avatar_url(origin: &InstanceOrigin, user: UserId, kind: ImageKind) -> String {
    format!(
        "{}{AVATARS_PATH_PREFIX}{}",
        origin.base_url(),
        AvatarFile { user, kind }
    )
}

/// The URL an upload is published at: where it is served, versioned by the upload time. The
/// store keeps one object per account and kind, so under an unchanged URL a browser — here or on
/// a peer — would keep showing the old image.
pub fn published_url(served: &str, uploaded_at: OffsetDateTime) -> String {
    format!("{served}?v={}", uploaded_at.unix_timestamp())
}

#[cfg(test)]
mod tests;
