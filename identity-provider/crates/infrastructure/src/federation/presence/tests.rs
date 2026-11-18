use std::net::SocketAddr;

use domain::presence::{PresenceEvent, TypingEvent};
use federation_transport::UrlPolicy;
use futures_util::StreamExt;
use jwt_utils::load_ed_keypair;
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
    let keypair = load_ed_keypair(&path, Some("test-key")).unwrap();
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

    let none = frames.push(b"event: presence\ndata: {").unwrap();
    let first = frames
        .push(b"}\n\nevent: typing\r\ndata: x\r\n\r\n: keep")
        .unwrap();
    let last = frames.push(b"-alive\n\n").unwrap();

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
fn a_blank_line_split_across_chunks_still_ends_its_frame() {
    let mut frames = Frames::default();

    let crlf = [
        frames.push(b"data: a\r\n\r").unwrap(),
        frames.push(b"\n").unwrap(),
    ];
    let lf = [
        frames.push(b"data: b\n").unwrap(),
        frames.push(b"\ndata: c\n").unwrap(),
        frames.push(b"\n").unwrap(),
    ];

    assert_eq!(crlf, [vec![], vec!["data: a".to_owned()]]);
    assert_eq!(
        lf,
        [
            vec![],
            vec!["data: b".to_owned()],
            vec!["data: c".to_owned()]
        ]
    );
}

#[test]
fn a_frame_past_the_cap_is_refused_however_it_arrives() {
    let line = |n: usize| format!("data: {}", "x".repeat(n - 6));
    let mut piecemeal = Frames::default();
    let mut whole = Frames::default();

    let under = piecemeal.push(line(MAX_FRAME_BYTES).as_bytes());
    let over = piecemeal.push(b"x");
    let in_one_chunk = whole.push(format!("{}\n\n", line(MAX_FRAME_BYTES + 1)).as_bytes());
    let at_the_cap = Frames::default().push(format!("{}\n\n", line(MAX_FRAME_BYTES)).as_bytes());

    assert!(under.is_ok_and(|frames| frames.is_empty()));
    assert!(over.is_err());
    assert!(in_one_chunk.is_err());
    assert!(at_the_cap.is_ok_and(|frames| frames.len() == 1));
}

#[tokio::test]
async fn a_stream_that_never_ends_a_frame_is_ended_past_the_cap() {
    let (address, _) = peer(|_| {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n\
             event: presence\ndata: {}",
            "x".repeat(MAX_FRAME_BYTES)
        )
    })
    .await;
    let (source, _received) = source();

    let ended = source
        .stream(&domain_of(address), &[carol_at(address)])
        .await;

    assert!(
        ended
            .as_ref()
            .is_err_and(|e| e.to_string().contains("is over 16384 bytes")),
        "{ended:?}"
    );
}

#[test]
fn only_a_well_formed_presence_or_typing_frame_is_a_signal() {
    assert_eq!(read_frame(": keep-alive"), Ok(None));
    assert_eq!(read_frame("event: other\ndata: {}"), Ok(None));
    assert_eq!(
        read_frame("event: presence\ndata: not json"),
        Err(Malformed("presence"))
    );
    assert!(matches!(
        read_frame(
            "id: 7\nevent: presence\ndata: {\"type\":\"presence\",\"event\":\"online\",\"actorUri\":\"http://localhost:8080/users/alice_t3st0\",\"timestamp\":\"2026-09-29T12:00:00Z\"}"
        ),
        Ok(Some(Signal::Presence(_)))
    ));
}

/// A stream source on the development policy, and what it hears.
fn source() -> (Source, mpsc::Receiver<(Domain, Signal)>) {
    let (heard, received) = mpsc::channel(HEARD_BOUND);
    let source = Source {
        keypair: keypair(),
        origin: origin(),
        policy: dev(),
        heard,
    };
    (source, received)
}

fn presence_frame(actor: &ActorUri) -> String {
    format!(
        "event: presence\ndata: {{\"type\":\"presence\",\"event\":\"online\",\"actorUri\":\"{actor}\",\"timestamp\":\"2026-09-29T12:00:00Z\"}}\n\n"
    )
}

fn event_stream(body: &str) -> String {
    format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n{body}")
}

#[tokio::test]
async fn a_peer_outpacing_the_bus_waits_on_its_own_connection() {
    let sent = HEARD_BOUND * 4;
    let (address, _) =
        peer(move |address| event_stream(&presence_frame(&carol_at(address)).repeat(sent))).await;
    let (source, mut received) = source();
    let peer_domain = domain_of(address);
    let carol = carol_at(address);

    let streaming = tokio::spawn(async move {
        source
            .stream(&peer_domain, std::slice::from_ref(&carol))
            .await
    });
    let filled = tokio::time::timeout(Duration::from_secs(5), async {
        while received.len() < HEARD_BOUND {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let held = received.len();
    let waiting = !streaming.is_finished();
    let mut heard = 0;
    while received.recv().await.is_some() {
        heard += 1;
    }

    assert!(filled.is_ok());
    assert_eq!((held, waiting), (HEARD_BOUND, true));
    assert_eq!(heard, sent);
    assert!(streaming.await.unwrap().is_ok());
}

/// Counts the events at WARN or above.
#[derive(Clone, Default)]
struct Loud(Arc<std::sync::atomic::AtomicUsize>);

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Loud {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        if *event.metadata().level() <= tracing::Level::WARN {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

#[tokio::test]
async fn a_stream_warns_of_its_first_malformed_signal_only() {
    use tracing_subscriber::layer::SubscriberExt;

    let loud = Loud::default();
    let _guard =
        tracing::subscriber::set_default(tracing_subscriber::registry().with(loud.clone()));
    let (address, _) = peer(|address| {
        event_stream(&format!(
            "{}{}",
            "event: typing\ndata: {}\n\n".repeat(50),
            presence_frame(&carol_at(address))
        ))
    })
    .await;
    let (source, mut received) = source();

    let ended = source
        .stream(&domain_of(address), &[carol_at(address)])
        .await;

    assert!(ended.is_ok(), "{ended:?}");
    assert!(matches!(received.try_recv(), Ok((_, Signal::Presence(_)))));
    assert_eq!(loud.0.load(std::sync::atomic::Ordering::SeqCst), 1);
}
