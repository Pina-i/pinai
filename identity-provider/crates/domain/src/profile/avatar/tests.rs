use super::*;

fn image(content_type: Option<&str>, len: usize) -> Result<AvatarImage, ValidationError> {
    AvatarImage::parse(content_type, Bytes::from(vec![7u8; len]))
}

#[test]
fn an_avatar_is_a_jpeg_png_webp_or_gif_image() {
    for kind in ImageKind::ALL {
        assert_eq!(image(Some(kind.mime()), 10).unwrap().kind(), kind);
    }

    for (content_type, reason) in [
        (None, "Content-Type header is required"),
        (
            Some("image/svg+xml"),
            "Content-Type must be image/jpeg, image/png, image/webp, or image/gif",
        ),
        (
            Some("image/png; charset=binary"),
            "Content-Type must be image/jpeg, image/png, image/webp, or image/gif",
        ),
    ] {
        assert_eq!(image(content_type, 10).unwrap_err().reason, reason);
    }
}

#[test]
fn an_avatar_holds_one_byte_to_two_mebibytes() {
    assert!(image(Some("image/png"), AvatarImage::MAX_BYTES).is_ok());

    let empty = image(Some("image/png"), 0).unwrap_err();
    let large = image(Some("image/png"), AvatarImage::MAX_BYTES + 1).unwrap_err();

    assert_eq!(empty.reason, "Body cannot be empty");
    assert_eq!(large.reason, "Avatar must be under 2 MiB");
}

#[test]
fn an_avatar_is_published_under_its_upload_time() {
    let at = OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap();

    assert_eq!(
        published_url("http://s3.test/avatars/u.png", at),
        "http://s3.test/avatars/u.png?v=1790000000"
    );
}
