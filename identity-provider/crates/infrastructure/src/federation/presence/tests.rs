use std::net::SocketAddr;

use domain::presence::{PresenceEvent, TypingEvent};
use federation_transport::UrlPolicy;
use futures_util::StreamExt;
use jwt_utils::load_ed_keypair_from_pem;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

use super::*;

// Minted for these tests only.
const TEST_KEY: &str = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIF1VRwFuAo+gfSZtIUeF2VmNnVy0VePE+L7/D1UTTV6/
-----END PRIVATE KEY-----
";

fn keypair() -> Arc<EdKeyPair> {
    let path = std::env::temp_dir().join(format!("pinai-presence-{}.pem", uuid::Uuid::new_v4()));
    std::fs::write(&path, TEST_KEY).unwrap();
    let keypair = load_ed_keypair_from_pem(&path, "test-key").unwrap();
    std::fs::remove_file(&path).unwrap();
    Arc::new(keypair)
}

fn origin() -> InstanceOrigin {
    InstanceOrigin::parse("http://localhost:8080").unwrap()
}

fn dev() -> UrlPolicy {
    UrlPolicy::from_issuer("http://localhost:8080")
}

fn production() -> (InstanceOrigin, UrlPolicy) {
    (
        InstanceOrigin::parse("https://idp.alice.test").unwrap(),
        UrlPolicy::from_issuer("https://idp.alice.test"),
    )
}

/// Whether anything reached the peer in a moment.
async fn asked(received: oneshot::Receiver<String>) -> bool {
    tokio::time::timeout(Duration::from_millis(300), received)
        .await
        .is_ok()
}

/// A peer on the loopback interface that answers once with what `respond` makes of its own
/// address, and hands back what it was sent.
async fn peer(
    respond: impl FnOnce(SocketAddr) -> String + Send + 'static,
) -> (SocketAddr, oneshot::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (sent, received) = oneshot::channel();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = vec![0; 8192];
        let n = socket.read(&mut request).await.unwrap();
        let _ = sent.send(String::from_utf8_lossy(&request[..n]).into_owned());
        let _ = socket.write_all(respond(address).as_bytes()).await;
        let _ = socket.shutdown().await;
    });
    (address, received)
}

fn json(body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn carol_at(address: SocketAddr) -> ActorUri {
    ActorUri::parse(&format!("http://{address}/users/carol_t3st0")).unwrap()
}

fn domain_of(address: SocketAddr) -> Domain {
    Domain::parse(&address.to_string()).unwrap()
}

fn at() -> OffsetDateTime {
    OffsetDateTime::parse("2026-09-29T12:00:00Z", &Rfc3339).unwrap()
}

#[tokio::test]
async fn a_poll_is_signed_as_the_instance_and_answered_per_actor() {
    let (address, received) = peer(|address| {
        json(&format!(
            r#"{{"presence":[{{"actorUri":"{}","state":"dnd"}},{{"actorUri":"not a uri","state":"online"}}]}}"#,
            carol_at(address)
        ))
    })
    .await;
    let carol = carol_at(address);

    let answered = SignedPeerPresence::new(keypair(), origin(), dev())
        .poll(&domain_of(address), std::slice::from_ref(&carol))
        .await
        .unwrap();

    assert_eq!(answered, vec![(carol.clone(), PresenceState::Dnd)]);
    let request = received.await.unwrap();
    assert!(
        request.starts_with("POST /api/presence/batch HTTP/1.1"),
        "{request}"
    );
    assert!(
        request.contains(r#"keyId="http://localhost:8080/actor#main-key""#),
        "{request}"
    );
    assert!(
        request.contains(&format!(r#"{{"actors":["{carol}"]}}"#)),
        "{request}"
    );
}

#[tokio::test]
async fn a_watched_conversation_streams_its_members_signals_from_their_instance() {
    let conversation = ConversationId::generate();
    let (address, received) = peer(move |address| {
        let carol = carol_at(address);
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n\
             :keep-alive\n\n\
             id: 1\nevent: presence\ndata: {{\"type\":\"presence\",\"event\":\"away\",\"actorUri\":\"{carol}\",\"timestamp\":\"2026-09-29T12:00:00Z\"}}\n\n\
             id: 2\r\nevent: typing\r\ndata: {{\"type\":\"typing\",\"actorUri\":\"{carol}\",\"conversationId\":\"{conversation}\",\"timestamp\":\"2026-09-29T12:00:00Z\"}}\r\n\r\n"
        )
    })
    .await;
    let carol = carol_at(address);
    let (streams, mut heard) = SsePeerStreams::new(keypair(), origin(), dev());

    streams
        .watch(
            conversation,
            [(domain_of(address), vec![carol.clone()])].into(),
        )
        .await;
    let first = heard.next().await.unwrap();
    let second = heard.next().await.unwrap();

    assert_eq!(
        (first, second),
        (
            (
                domain_of(address),
                Signal::Presence(PresenceEvent {
                    actor: carol.clone(),
                    state: PresenceState::Away,
                    at: at(),
                })
            ),
            (
                domain_of(address),
                Signal::Typing(TypingEvent {
                    actor: carol.clone(),
                    conversation,
                    at: at(),
                })
            ),
        )
    );
    let request = received.await.unwrap();
    let asked: String = url::form_urlencoded::byte_serialize(carol.as_str().as_bytes()).collect();
    assert!(
        request.starts_with(&format!(
            "GET /api/presence/stream?actors%5B%5D={asked} HTTP/1.1"
        )),
        "{request}"
    );
    assert!(
        request.contains(r#"keyId="http://localhost:8080/actor#main-key""#),
        "{request}"
    );
}

#[tokio::test]
async fn watching_another_conversation_with_the_same_members_opens_the_stream_again() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (opened, mut opens) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let _ = opened.send(());
            tokio::spawn(async move {
                let mut request = vec![0; 8192];
                let _ = socket.read(&mut request).await;
                let _ = socket
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n")
                    .await;
                tokio::time::sleep(Duration::from_secs(5)).await;
            });
        }
    });
    let carol = carol_at(address);
    let members = || [(domain_of(address), vec![carol.clone()])].into();
    let (dm, group) = (ConversationId::generate(), ConversationId::generate());
    let (streams, _heard) = SsePeerStreams::new(keypair(), origin(), dev());
    let next = async |opens: &mut mpsc::UnboundedReceiver<()>| {
        tokio::time::timeout(Duration::from_millis(500), opens.recv())
            .await
            .is_ok()
    };

    streams.watch(dm, members()).await;
    let first = next(&mut opens).await;
    streams.watch(dm, members()).await;
    let again = next(&mut opens).await;
    streams.watch(group, members()).await;
    let another = next(&mut opens).await;

    assert_eq!((first, again, another), (true, false, true));
}

#[tokio::test]
async fn a_public_instance_never_polls_a_private_address() {
    let (address, received) = peer(|_| json(r#"{"presence":[]}"#)).await;
    let (origin, policy) = production();

    let refused = SignedPeerPresence::new(keypair(), origin, policy)
        .poll(&domain_of(address), &[carol_at(address)])
        .await;

    assert!(refused.is_err(), "{refused:?}");
    assert!(!asked(received).await);
}

#[tokio::test]
async fn a_public_instance_never_streams_from_a_private_address() {
    let (address, received) = peer(|_| json("")).await;
    let (origin, policy) = production();
    let (streams, _heard) = SsePeerStreams::new(keypair(), origin, policy);

    streams
        .watch(
            ConversationId::generate(),
            [(domain_of(address), vec![carol_at(address)])].into(),
        )
        .await;

    assert!(!asked(received).await);
}

#[tokio::test]
async fn a_poll_answer_past_the_body_cap_is_refused() {
    let (address, _) = peer(|_| {
        json(&format!(
            r#"{{"presence":[],"padding":"{}"}}"#,
            "x".repeat(300 * 1024)
        ))
    })
    .await;

    let refused = SignedPeerPresence::new(keypair(), origin(), dev())
        .poll(&domain_of(address), &[carol_at(address)])
        .await;

    assert!(refused.is_err(), "{refused:?}");
}

#[test]
fn frames_are_read_whole_whatever_the_chunks() {
    let mut frames = Frames::default();

    let none = frames.push(b"event: presence\ndata: {");
    let first = frames.push(b"}\n\nevent: typing\r\ndata: x\r\n\r\n: keep");
    let last = frames.push(b"-alive\n\n");

    assert!(none.is_empty());
    assert_eq!(
        first,
        vec![
            "event: presence\ndata: {}".to_owned(),
            "event: typing\r\ndata: x".to_owned()
        ]
    );
    assert_eq!(last, vec![": keep-alive".to_owned()]);
}

#[test]
fn only_a_well_formed_presence_or_typing_frame_is_a_signal() {
    assert_eq!(read_frame(": keep-alive"), None);
    assert_eq!(read_frame("event: other\ndata: {}"), None);
    assert_eq!(read_frame("event: presence\ndata: not json"), None);
    assert!(matches!(
        read_frame(
            "id: 7\nevent: presence\ndata: {\"type\":\"presence\",\"event\":\"online\",\"actorUri\":\"http://localhost:8080/users/alice_t3st0\",\"timestamp\":\"2026-09-29T12:00:00Z\"}"
        ),
        Some(Signal::Presence(_))
    ));
}
