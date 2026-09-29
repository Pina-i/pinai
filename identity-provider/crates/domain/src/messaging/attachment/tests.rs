use super::*;

fn limits() -> AttachmentLimits {
    AttachmentLimits {
        max_files: 2,
        max_bytes: 1_000,
        blocked_mimes: vec!["application/x-msdownload".to_owned()],
        blocked_extensions: vec!["exe".to_owned()],
    }
}

fn bob() -> ActorUri {
    ActorUri::parse("https://idp.bob.test/users/bob_k2m9x").unwrap()
}

fn document(id: AttachmentId) -> OfferedAttachment {
    OfferedAttachment {
        is_document: true,
        url: Some(format!("https://idp.bob.test/api/attachments/{id}/content")),
        media_type: Some("image/png".to_owned()),
        name: Some("cat.png".to_owned()),
        size: Some(512),
    }
}

#[test]
fn a_document_within_the_limits_is_recorded_under_the_senders_id() {
    let id = AttachmentId::generate();

    let admitted = limits().admit(&[document(id)], &bob());

    assert_eq!(
        admitted,
        vec![Ok(RemoteAttachment {
            id,
            url: format!("https://idp.bob.test/api/attachments/{id}/content"),
            mime_type: "image/png".to_owned(),
            byte_size: 512,
            original_filename: "cat.png".to_owned(),
        })]
    );
}

#[test]
fn only_the_first_offers_up_to_the_limit_are_considered() {
    let offers: Vec<_> = (0..3).map(|_| document(AttachmentId::generate())).collect();

    assert_eq!(limits().admit(&offers, &bob()).len(), 2);
}

#[test]
fn an_offer_the_limits_refuse_is_skipped_with_its_reason() {
    let fine = document(AttachmentId::generate());
    let refused = [
        OfferedAttachment {
            is_document: false,
            ..fine.clone()
        },
        OfferedAttachment {
            url: None,
            ..fine.clone()
        },
        OfferedAttachment {
            url: Some(String::new()),
            ..fine.clone()
        },
        OfferedAttachment {
            media_type: None,
            ..fine.clone()
        },
        OfferedAttachment {
            size: None,
            ..fine.clone()
        },
        OfferedAttachment {
            size: Some(0),
            ..fine.clone()
        },
        OfferedAttachment {
            size: Some(1_001),
            ..fine.clone()
        },
        OfferedAttachment {
            media_type: Some("Application/X-MSDownload".to_owned()),
            ..fine.clone()
        },
    ];
    let limits = AttachmentLimits {
        max_files: 10,
        ..limits()
    };

    let admitted = limits.admit(&refused, &bob());

    assert_eq!(admitted.len(), refused.len());
    assert!(admitted.iter().all(Result::is_err), "{admitted:?}");
}

#[test]
fn an_unnamed_attachment_is_called_attachment() {
    let offer = OfferedAttachment {
        name: None,
        ..document(AttachmentId::generate())
    };

    let admitted = limits().admit(&[offer], &bob());

    assert_eq!(
        admitted[0].as_ref().unwrap().original_filename,
        "attachment"
    );
}

#[test]
fn a_content_url_without_an_id_gets_a_fresh_one() {
    let id = AttachmentId::generate();

    assert_eq!(
        AttachmentId::of_content_url(&format!(
            "https://idp.bob.test/api/attachments/{id}/content"
        )),
        id
    );
    assert_eq!(
        AttachmentId::of_content_url(&format!("https://idp.bob.test/api/attachments/{id}")),
        id
    );
    assert_ne!(
        AttachmentId::of_content_url("https://cdn.test/cat.png"),
        AttachmentId::of_content_url("https://cdn.test/cat.png")
    );
}

fn uri(name: &str) -> ActorUri {
    ActorUri::parse(&format!("https://idp.test/users/{name}")).unwrap()
}

fn member(actor: &ActorUri) -> Member {
    Member {
        actor_uri: actor.clone(),
        role: crate::messaging::Role::Member,
    }
}

#[test]
fn a_file_is_refused_before_its_bytes_are_read_by_extension_or_mime_type() {
    let limits = limits();

    assert!(limits.check_file("cat.png", "image/png").is_ok());
    assert_eq!(
        limits.check_file("setup.EXE", "application/octet-stream"),
        Err(UploadRefusal::BlockedExtension("exe".to_owned()))
    );
    assert_eq!(
        limits.check_file("setup", "Application/X-MSDownload"),
        Err(UploadRefusal::BlockedMime(
            "Application/X-MSDownload".to_owned()
        ))
    );
    assert!(
        limits.check_file(".exe", "text/plain").is_ok(),
        "a dot file has no extension"
    );
}

#[test]
fn an_uploaded_file_is_never_empty_nor_over_the_size_limit() {
    let file = |bytes: usize| {
        UploadFile::new(
            &limits(),
            "cat.png".into(),
            "image/png".into(),
            vec![1; bytes],
        )
    };

    assert_eq!(file(1_000).unwrap().len(), 1_000);
    assert_eq!(file(0), Err(UploadRefusal::Empty("cat.png".to_owned())));
    assert_eq!(
        file(1_001),
        Err(UploadRefusal::TooLarge {
            filename: "cat.png".to_owned(),
            max: 1_000
        })
    );
}

#[test]
fn an_upload_holds_one_to_max_files_and_a_chosen_id_needs_exactly_one() {
    let limits = limits();

    assert!(limits.check_count(2).is_ok());
    assert_eq!(limits.check_count(3), Err(UploadRefusal::TooManyFiles(2)));
    assert_eq!(limits.check_batch(0, false), Err(UploadRefusal::NoFiles));
    assert!(limits.check_batch(2, false).is_ok());
    assert!(limits.check_batch(1, true).is_ok());
    assert_eq!(
        limits.check_batch(2, true),
        Err(UploadRefusal::ChosenIdNeedsOneFile)
    );
}

#[test]
fn an_attachment_is_read_by_its_uploader_and_the_conversation_it_was_sent_in() {
    let (ana, bo, eve) = (uri("ana"), uri("bo"), uri("eve"));
    let orphan = Attachment {
        id: AttachmentId::generate(),
        uploader: ana.clone(),
        message: None,
        mime_type: "image/png".to_owned(),
        byte_size: 1,
        original_filename: "cat.png".to_owned(),
        remote_url: None,
    };
    let sent = Attachment {
        message: Some(crate::MessageId::generate()),
        ..orphan.clone()
    };
    let conversation = [member(&ana), member(&bo)];

    assert!(orphan.readable_by(&ana, &[]));
    assert!(
        !orphan.readable_by(&bo, &[]),
        "an orphan is its uploader's alone"
    );
    assert!(sent.readable_by(&bo, &conversation));
    assert!(!sent.readable_by(&eve, &conversation));
}

#[test]
fn a_peer_fetches_an_attachment_only_for_a_conversation_it_has_a_member_in() {
    let members = [
        member(&uri("ana")),
        member(&ActorUri::parse("https://idp.bob.test:8443/users/bo").unwrap()),
    ];
    let bobs = ActorUri::parse("https://idp.bob.test:8443/actor").unwrap();

    assert!(peer_may_fetch(&members, &bobs));
    for stranger in [
        "https://idp.eve.test/actor",
        "https://idp.bob.test/actor",
        "http://idp.bob.test:8443/actor",
    ] {
        assert!(
            !peer_may_fetch(&members, &ActorUri::parse(stranger).unwrap()),
            "{stranger}"
        );
    }
}

#[tokio::test]
async fn a_stream_limited_to_a_size_ends_in_an_error_past_it() {
    use crate::messaging::testing::{byte_chunks, collect};

    let within = byte_chunks(vec![vec![1; 3], vec![2; 2]]).limited_to(5);
    let past = byte_chunks(vec![vec![1; 3], vec![2; 3]]).limited_to(5);

    assert_eq!(collect(within).await.unwrap(), [1, 1, 1, 2, 2]);
    assert!(collect(past).await.is_err());
}

#[test]
fn an_attachment_hosted_anywhere_but_the_senders_own_content_endpoint_is_refused() {
    let id = AttachmentId::generate();
    let at = |url: String| OfferedAttachment {
        url: Some(url),
        ..document(id)
    };

    let admitted = limits().admit(
        &[at(format!(
            "https://idp.bob.test/api/attachments/{id}/content"
        ))],
        &bob(),
    );
    assert!(admitted[0].is_ok());
    for elsewhere in [
        format!("https://cdn.test/api/attachments/{id}/content"),
        format!("http://idp.bob.test/api/attachments/{id}/content"),
        format!("https://idp.bob.test:8443/api/attachments/{id}/content"),
        "https://idp.bob.test/files/cat.png".to_owned(),
        "http://169.254.169.254/latest/meta-data/".to_owned(),
    ] {
        let limits = AttachmentLimits {
            max_files: 10,
            ..limits()
        };
        let refused = limits.admit(&[at(elsewhere.clone())], &bob());
        assert!(refused[0].is_err(), "{elsewhere}");
    }
}
