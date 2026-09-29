use std::sync::Arc;

use domain::identity::testing::{InMemoryAccounts, account};
use domain::identity::{Account, ActorUri};
use domain::messaging::testing::{
    InMemoryMessaging, InMemoryObjects, InMemoryRemoteFiles, PlainBlobTokens, collect,
    contract::{an_upload, new_message},
};
use domain::messaging::{
    Attachment, AttachmentError, AttachmentLimits, Attachments, BlobTokens, Conversations,
    Messages, NewMessage, RemoteAttachment, UploadFile, UploadRefusal,
};
use domain::{AttachmentId, ConversationId};
use time::{Duration, OffsetDateTime};

use super::*;

struct World {
    alice: Account,
    bob: Account,
    eve: Account,
    carol: ActorUri,
    accounts: Arc<InMemoryAccounts>,
    store: Arc<InMemoryMessaging>,
    objects: Arc<InMemoryObjects>,
    remote: Arc<InMemoryRemoteFiles>,
    tokens: Arc<PlainBlobTokens>,
}

const CAROLS_FILE: &str =
    "https://idp.carol.test/api/attachments/11111111-1111-4111-8111-111111111111/content";

/// Alice and Bob share a DM; Eve is here too; Carol writes to Alice from another instance.
fn world() -> World {
    let (alice, bob, eve) = (account("alice"), account("bob"), account("eve"));
    World {
        accounts: Arc::new(InMemoryAccounts::with([
            alice.clone(),
            bob.clone(),
            eve.clone(),
        ])),
        alice,
        bob,
        eve,
        carol: ActorUri::parse("https://idp.carol.test/users/carol_k2m9x").unwrap(),
        store: Arc::new(InMemoryMessaging::default()),
        objects: Arc::new(InMemoryObjects::default()),
        remote: Arc::new(InMemoryRemoteFiles::with([(
            CAROLS_FILE.to_owned(),
            b"carol's bytes".to_vec(),
        )])),
        tokens: Arc::new(PlainBlobTokens),
    }
}

fn limits() -> AttachmentLimits {
    AttachmentLimits {
        max_files: 5,
        max_bytes: 1_000,
        blocked_mimes: Vec::new(),
        blocked_extensions: Vec::new(),
    }
}

fn file(name: &str, bytes: &[u8]) -> UploadFile {
    UploadFile::new(
        &limits(),
        name.to_owned(),
        "image/png".to_owned(),
        bytes.to_vec(),
    )
    .unwrap()
}

fn upload(w: &World) -> UploadAttachments {
    UploadAttachments::new(
        limits(),
        w.accounts.clone(),
        w.store.clone(),
        w.objects.clone(),
    )
}

fn open(w: &World) -> OpenAttachment {
    OpenAttachment::new(
        w.accounts.clone(),
        w.store.clone(),
        w.store.clone(),
        w.store.clone(),
        w.tokens.clone(),
    )
}

fn read(w: &World) -> ReadBlob {
    ReadBlob::new(
        w.store.clone(),
        w.tokens.clone(),
        w.objects.clone(),
        w.remote.clone(),
    )
}

fn serve(w: &World) -> ServePeerContent {
    ServePeerContent::new(
        w.store.clone(),
        w.store.clone(),
        w.store.clone(),
        w.objects.clone(),
    )
}

/// An upload of Alice's, its bytes stored.
async fn alices_upload(w: &World) -> Attachment {
    let upload = an_upload(&w.alice.actor_uri);
    w.store.record_upload(&upload).await.unwrap();
    w.objects.insert(upload.id, b"alice's bytes".to_vec());
    upload
}

/// Alice's upload, sent to Bob — or to Carol on her instance.
async fn sent_to(w: &World, to: &ActorUri) -> (Attachment, ConversationId) {
    let upload = alices_upload(w).await;
    let dm = w.store.open_dm(&w.alice.actor_uri, to, None).await.unwrap();
    w.store
        .record(&NewMessage {
            attachments: vec![upload.id],
            ..new_message(dm, &w.alice.actor_uri)
        })
        .await
        .unwrap();
    (
        Attachments::find(&*w.store, upload.id)
            .await
            .unwrap()
            .unwrap(),
        dm,
    )
}

/// An attachment Carol's instance hosts, recorded for her message to Alice.
async fn carols(w: &World) -> AttachmentId {
    let dm = w
        .store
        .open_dm(&w.carol, &w.alice.actor_uri, None)
        .await
        .unwrap();
    let id = AttachmentId::of_content_url(CAROLS_FILE);
    w.store
        .record_received(
            &new_message(dm, &w.carol),
            &[RemoteAttachment {
                id,
                url: CAROLS_FILE.to_owned(),
                mime_type: "image/png".to_owned(),
                byte_size: 13,
                original_filename: "cat.png".to_owned(),
            }],
        )
        .await
        .unwrap();
    id
}

#[tokio::test]
async fn an_upload_is_stored_and_recorded_as_its_uploaders_orphans() {
    let w = world();

    let views = upload(&w)
        .execute(
            w.alice.id,
            vec![file("a.png", b"aaa"), file("b.png", b"bb")],
            None,
        )
        .await
        .unwrap();

    assert_eq!(views.len(), 2);
    for (view, bytes) in views.iter().zip([b"aaa".to_vec(), b"bb".to_vec()]) {
        let recorded = Attachments::find(&*w.store, view.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            (&recorded.uploader, recorded.message),
            (&w.alice.actor_uri, None)
        );
        assert_eq!(recorded.view(), *view);
        assert_eq!(w.objects.holds(view.id), Some(bytes));
    }
}

#[tokio::test]
async fn a_chosen_id_names_the_single_file() {
    let w = world();
    let chosen = AttachmentId::generate();

    let views = upload(&w)
        .execute(w.alice.id, vec![file("a.png", b"aaa")], Some(chosen))
        .await
        .unwrap();

    assert_eq!(views[0].id, chosen);
}

#[tokio::test]
async fn an_upload_refused_as_a_whole_stores_nothing() {
    let w = world();

    let none = upload(&w).execute(w.alice.id, Vec::new(), None).await;
    let two_under_one_id = upload(&w)
        .execute(
            w.alice.id,
            vec![file("a.png", b"a"), file("b.png", b"b")],
            Some(AttachmentId::generate()),
        )
        .await;

    assert!(matches!(
        none,
        Err(AttachmentError::Refused(UploadRefusal::NoFiles))
    ));
    assert!(matches!(
        two_under_one_id,
        Err(AttachmentError::Refused(
            UploadRefusal::ChosenIdNeedsOneFile
        ))
    ));
}

#[tokio::test]
async fn an_upload_the_store_cannot_take_leaves_no_record_behind() {
    let w = world();
    let broken = UploadAttachments::new(
        limits(),
        w.accounts.clone(),
        w.store.clone(),
        Arc::new(InMemoryObjects::unavailable()),
    );
    let chosen = AttachmentId::generate();

    let failed = broken
        .execute(w.alice.id, vec![file("a.png", b"a")], Some(chosen))
        .await;

    assert!(matches!(failed, Err(AttachmentError::Unexpected(_))));
    assert_eq!(Attachments::find(&*w.store, chosen).await.unwrap(), None);
}

#[tokio::test]
async fn the_uploader_opens_an_orphan_with_a_token_for_its_bytes() {
    let w = world();
    let upload = alices_upload(&w).await;

    let opened = open(&w).execute(w.alice.id, upload.id).await.unwrap();

    assert_eq!(opened.attachment, upload);
    assert_eq!(
        w.tokens.verify(&opened.token).unwrap(),
        (w.alice.id, upload.id)
    );
    assert!(opened.expires_at > OffsetDateTime::now_utc());
}

#[tokio::test]
async fn a_sent_attachment_opens_for_its_conversation_only() {
    let w = world();
    let (sent, _) = sent_to(&w, &w.bob.actor_uri).await;
    let orphan = alices_upload(&w).await;

    assert!(open(&w).execute(w.bob.id, sent.id).await.is_ok());
    for (who, id) in [(&w.eve, sent.id), (&w.bob, orphan.id)] {
        let refused = open(&w).execute(who.id, id).await;
        assert!(
            matches!(refused, Err(AttachmentError::Forbidden)),
            "{}",
            who.username
        );
    }
    let unknown = open(&w).execute(w.bob.id, AttachmentId::generate()).await;
    assert!(matches!(unknown, Err(AttachmentError::NotFound)));
}

#[tokio::test]
async fn a_token_reads_a_local_attachments_bytes() {
    let w = world();
    let upload = alices_upload(&w).await;
    let (token, _) = w.tokens.mint(w.alice.id, upload.id);

    let blob = read(&w).execute(upload.id, &token).await.unwrap();

    assert_eq!(
        (blob.mime_type.as_str(), blob.original_filename.as_str()),
        ("image/png", "cat.png")
    );
    assert_eq!(collect(blob.bytes).await.unwrap(), b"alice's bytes");
}

#[tokio::test]
async fn a_remote_attachment_is_read_from_the_instance_that_hosts_it() {
    let w = world();
    let id = carols(&w).await;
    let (token, _) = w.tokens.mint(w.alice.id, id);

    let blob = read(&w).execute(id, &token).await.unwrap();

    assert_eq!(collect(blob.bytes).await.unwrap(), b"carol's bytes");
    assert_eq!(w.remote.fetched(), vec![CAROLS_FILE.to_owned()]);
}

#[tokio::test]
async fn a_blob_is_refused_without_a_valid_token_for_it() {
    let w = world();
    let upload = alices_upload(&w).await;
    let (for_another, _) = w.tokens.mint(w.alice.id, AttachmentId::generate());

    for (token, expected) in [
        (
            PlainBlobTokens::expired(w.alice.id, upload.id),
            "TokenExpired",
        ),
        ("forged".to_owned(), "TokenInvalid"),
        (for_another, "TokenMismatch"),
    ] {
        let refused = read(&w).execute(upload.id, &token).await.map(|_| ());
        assert_eq!(
            refused.map_err(|e| format!("{e:?}")),
            Err(expected.to_owned())
        );
    }
}

#[tokio::test]
async fn a_peer_with_a_member_in_the_conversation_gets_the_bytes() {
    let w = world();
    let (sent, _) = sent_to(&w, &w.carol).await;
    let carols_instance = ActorUri::parse("https://idp.carol.test/actor").unwrap();

    let blob = serve(&w).execute(&carols_instance, sent.id).await.unwrap();

    assert_eq!(collect(blob.bytes).await.unwrap(), b"alice's bytes");
}

#[tokio::test]
async fn a_peer_is_refused_what_it_may_not_fetch() {
    let w = world();
    let (sent, _) = sent_to(&w, &w.carol).await;
    let orphan = alices_upload(&w).await;
    let hosted_elsewhere = carols(&w).await;
    let stranger = ActorUri::parse("https://idp.eve.test/actor").unwrap();
    let carols_instance = ActorUri::parse("https://idp.carol.test/actor").unwrap();

    for (peer, id, expected) in [
        (&stranger, sent.id, "PeerNotInConversation"),
        (&carols_instance, orphan.id, "Unlinked"),
        (&carols_instance, hosted_elsewhere, "NotHostedHere"),
        (&carols_instance, AttachmentId::generate(), "NotFound"),
    ] {
        let refused = serve(&w).execute(peer, id).await.map(|_| ());
        assert_eq!(
            refused.map_err(|e| format!("{e:?}")),
            Err(expected.to_owned())
        );
    }
}

#[tokio::test]
async fn orphans_past_their_time_are_reaped_with_their_bytes() {
    let w = world();
    let orphan = alices_upload(&w).await;
    let (sent, _) = sent_to(&w, &w.bob.actor_uri).await;
    let sweep =
        SweepOrphanAttachments::new(Duration::minutes(30), w.store.clone(), w.objects.clone());

    let too_soon = sweep.execute(OffsetDateTime::now_utc()).await.unwrap();
    let reaped = sweep
        .execute(OffsetDateTime::now_utc() + Duration::minutes(31))
        .await
        .unwrap();

    assert_eq!((too_soon, reaped), (0, 1));
    assert_eq!(Attachments::find(&*w.store, orphan.id).await.unwrap(), None);
    assert_eq!(w.objects.holds(orphan.id), None);
    assert!(
        Attachments::find(&*w.store, sent.id)
            .await
            .unwrap()
            .is_some(),
        "a sent one stays"
    );
    assert!(w.objects.holds(sent.id).is_some());
}

#[tokio::test]
async fn an_upload_under_a_taken_id_is_refused_and_leaves_that_attachment_intact() {
    let w = world();
    let bobs = an_upload(&w.bob.actor_uri);
    w.store.record_upload(&bobs).await.unwrap();
    w.objects.insert(bobs.id, b"bob's bytes".to_vec());

    let refused = upload(&w)
        .execute(w.alice.id, vec![file("a.png", b"alice's")], Some(bobs.id))
        .await;

    assert!(
        matches!(refused, Err(AttachmentError::IdTaken)),
        "{:?}",
        refused.map(|_| ())
    );
    assert_eq!(w.objects.holds(bobs.id), Some(b"bob's bytes".to_vec()));
    assert_eq!(
        Attachments::find(&*w.store, bobs.id).await.unwrap(),
        Some(bobs)
    );
}

#[tokio::test]
async fn a_remote_attachment_is_cut_off_past_the_size_it_was_recorded_with() {
    let w = world();
    let dm = w
        .store
        .open_dm(&w.carol, &w.alice.actor_uri, None)
        .await
        .unwrap();
    let id = AttachmentId::of_content_url(CAROLS_FILE);
    w.store
        .record_received(
            &new_message(dm, &w.carol),
            &[RemoteAttachment {
                id,
                url: CAROLS_FILE.to_owned(),
                mime_type: "image/png".to_owned(),
                byte_size: 5,
                original_filename: "cat.png".to_owned(),
            }],
        )
        .await
        .unwrap();
    let (token, _) = w.tokens.mint(w.alice.id, id);

    let blob = read(&w).execute(id, &token).await.unwrap();

    assert!(
        collect(blob.bytes).await.is_err(),
        "the peer sent 13 bytes for 5"
    );
}
