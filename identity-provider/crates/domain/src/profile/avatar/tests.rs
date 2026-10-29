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
        published_url("https://bob.com/avatars/u.png", at),
        "https://bob.com/avatars/u.png?v=1790000000"
    );
}

const ID: &str = "550e8400-e29b-41d4-a716-446655440000";

#[test]
fn an_avatar_file_is_named_by_its_account_and_its_kind() {
    for (kind, extension) in [
        (ImageKind::Jpeg, "jpg"),
        (ImageKind::Png, "png"),
        (ImageKind::Webp, "webp"),
        (ImageKind::Gif, "gif"),
    ] {
        let name = format!("{ID}.{extension}");

        let file = AvatarFile::parse(&name).unwrap();

        assert_eq!(file.user.to_string(), ID);
        assert_eq!(file.kind, kind);
        assert_eq!(file.to_string(), name);
    }
}

#[test]
fn a_name_no_avatar_has_is_refused() {
    for name in [
        format!("{ID}.svg"),
        format!("{ID}.jpeg"),
        format!("{ID}.PNG"),
        ID.to_owned(),
        format!("{ID}."),
        format!("../{ID}.png"),
        format!("avatars/{ID}.png"),
        format!("{ID}.png/x"),
        "not-a-uuid.png".to_owned(),
        format!("{}.png", ID.replace('-', "")),
        format!("{}.png", ID.to_uppercase()),
        format!("{{{ID}}}.png"),
        format!("{ID}.png?v=1790000000"),
        String::new(),
    ] {
        assert_eq!(AvatarFile::parse(&name), None, "{name}");
    }
}

#[test]
fn an_avatar_is_served_by_its_own_instance() {
    let origin = InstanceOrigin::parse("https://bob.com").unwrap();
    let user = UserId::from(uuid::Uuid::parse_str(ID).unwrap());

    assert_eq!(
        avatar_url(&origin, user, ImageKind::Webp),
        format!("https://bob.com/avatars/{ID}.webp")
    );
}
