use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use super::*;

/// WebFinger's answer for `dave` at `at`, and his actor document.
fn dave_at(at: &str) -> (Value, Value) {
    let actor = format!("http://{at}/users/dave");
    let finger = json!({
        "subject": format!("acct:dave@{at}"),
        "links": [{ "rel": "self", "type": "application/activity+json", "href": actor }],
    });
    let document = serde_json::to_value(Actor::person(
        &format!("http://{at}"),
        "dave",
        "Dave",
        "-----BEGIN PUBLIC KEY-----",
    ))
    .unwrap();
    (finger, document)
}

/// A peer on the loopback interface answering WebFinger with the first of what `answers` gives
/// for the address it listens at, and anything else with the second.
async fn a_peer_with(answers: impl FnOnce(&str) -> (Value, Value)) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let at = listener.local_addr().unwrap().to_string();
    let (finger, document) = answers(&at);
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let (finger, document) = (finger.to_string(), document.to_string());
            tokio::spawn(async move {
                let mut request = [0; 4096];
                let read = socket.read(&mut request).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&request[..read]);
                let body = if request.contains("webfinger") {
                    finger
                } else {
                    document
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                     content-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
            });
        }
    });
    at
}

/// A peer answering WebFinger for `dave` and his actor document, with `icon`.
async fn a_peer(icon: Value) -> String {
    a_peer_with(|at| {
        let (finger, mut document) = dave_at(at);
        document["icon"] = icon;
        (finger, document)
    })
    .await
}

#[tokio::test]
async fn a_resolved_actor_brings_the_avatar_its_document_gives() {
    let domain = a_peer(json!({ "type": "Image", "url": "https://cdn.test/dave.png" })).await;

    let dave = resolve_remote_actor(
        "dave",
        &domain,
        "http",
        UrlPolicy::from_issuer("http://localhost"),
    )
    .await
    .unwrap();

    assert_eq!(dave.display_name.as_deref(), Some("Dave"));
    assert_eq!(
        dave.avatar_url.as_deref(),
        Some("https://cdn.test/dave.png")
    );
}

#[tokio::test]
async fn an_icon_given_as_a_list_brings_its_first_image() {
    let domain = a_peer(json!([
        { "type": "Image", "url": "https://cdn.test/first.png" },
        { "type": "Image", "url": "https://cdn.test/second.png" },
    ]))
    .await;

    let dave = resolve_remote_actor(
        "dave",
        &domain,
        "http",
        UrlPolicy::from_issuer("http://localhost"),
    )
    .await
    .unwrap();

    assert_eq!(
        dave.avatar_url.as_deref(),
        Some("https://cdn.test/first.png")
    );
}

#[tokio::test]
async fn a_peer_named_by_its_host_and_port_resolves_to_its_own_actor() {
    let at = a_peer_with(|at| dave_at(&at.replace("127.0.0.1", "localhost"))).await;
    let domain = at.replace("127.0.0.1", "localhost");

    let dave = resolve_remote_actor(
        "dave",
        &domain,
        "http",
        UrlPolicy::from_issuer("http://localhost"),
    )
    .await
    .unwrap();

    assert_eq!(
        dave.actor_url.as_str(),
        format!("http://{domain}/users/dave")
    );
    assert_eq!(
        dave.inbox.as_str(),
        format!("http://{domain}/users/dave/inbox")
    );
}

#[tokio::test]
async fn a_self_link_to_another_instance_is_refused() {
    let elsewhere = a_peer(Value::Null).await;
    let domain = a_peer_with(move |at| {
        let (mut finger, document) = dave_at(at);
        finger["links"][0]["href"] = json!(format!("http://{elsewhere}/users/dave"));
        (finger, document)
    })
    .await;

    let refused = resolving_dave_at(&domain).await;

    assert!(
        matches!(refused, Err(TransportError::Upstream(_))),
        "{refused:?}"
    );
}

#[tokio::test]
async fn a_document_naming_another_actor_than_the_one_fetched_is_refused() {
    for id in [
        "https://reef.chat/users/mahealani_q1x8c",
        "http://{at}/users/mahealani_q1x8c",
        "http://{at}/users/dave/",
        "dave",
    ] {
        let domain = a_peer_with(|at| {
            let (finger, mut document) = dave_at(at);
            document["id"] = json!(id.replace("{at}", at));
            (finger, document)
        })
        .await;

        let refused = resolving_dave_at(&domain).await;

        assert!(
            matches!(refused, Err(TransportError::Upstream(_))),
            "{id}: {refused:?}"
        );
    }
}

#[tokio::test]
async fn an_inbox_off_the_actors_instance_is_refused() {
    for inbox in [
        "https://reef.chat/users/mahealani_q1x8c/inbox",
        "https://{at}/users/dave/inbox",
        "file:///users/dave/inbox",
        "/users/dave/inbox",
        "not an inbox",
    ] {
        let domain = a_peer_with(|at| {
            let (finger, mut document) = dave_at(at);
            document["inbox"] = json!(inbox.replace("{at}", at));
            (finger, document)
        })
        .await;

        let refused = resolving_dave_at(&domain).await;

        assert!(
            matches!(refused, Err(TransportError::Upstream(_))),
            "{inbox}: {refused:?}"
        );
    }
}

#[tokio::test]
async fn a_document_fetched_by_its_url_is_kept_only_when_it_names_itself() {
    let dave = a_peer(Value::Null).await;
    let impostor = a_peer_with(|at| {
        let (finger, mut document) = dave_at(at);
        document["id"] = json!(format!("http://{dave}/users/dave"));
        (finger, document)
    })
    .await;
    let policy = UrlPolicy::from_issuer("http://localhost");

    let fetched = fetch_remote_actor(&format!("http://{dave}/users/dave"), policy).await;
    let refused = fetch_remote_actor(&format!("http://{impostor}/users/dave"), policy).await;

    assert_eq!(
        fetched.unwrap().inbox.as_str(),
        format!("http://{dave}/users/dave/inbox")
    );
    assert!(
        matches!(refused, Err(TransportError::Upstream(_))),
        "{refused:?}"
    );
}

#[tokio::test]
async fn a_domain_that_is_more_than_a_host_and_port_is_not_asked() {
    for domain in ["reef.chat/users", "dave@reef.chat", "reef.chat?x=1", ""] {
        let refused = resolving_dave_at(domain).await;

        assert!(
            matches!(refused, Err(TransportError::BadRequest(_))),
            "{domain}: {refused:?}"
        );
    }
}

/// A peer on the loopback interface answering every request with `status` and no body, and
/// telling each request's target to the receiver.
async fn a_peer_noting(status: &'static str) -> (String, mpsc::UnboundedReceiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let at = listener.local_addr().unwrap();
    let (asked, targets) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let mut request = [0; 4096];
            let read = socket.read(&mut request).await.unwrap_or(0);
            let request = String::from_utf8_lossy(&request[..read]);
            if let Some(target) = request.split(' ').nth(1) {
                let _ = asked.send(target.to_owned());
            }
            let response =
                format!("HTTP/1.1 {status}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
            let _ = socket.write_all(response.as_bytes()).await;
        }
    });
    (at.to_string(), targets)
}

#[tokio::test]
async fn webfinger_is_asked_for_the_whole_address_whatever_it_holds() {
    let (domain, mut targets) = a_peer_noting("404 Not Found").await;

    let unknown = resolve_remote_actor(
        "da#ve&rel=x?",
        &domain,
        "http",
        UrlPolicy::from_issuer("http://localhost"),
    )
    .await;

    assert!(
        matches!(unknown, Err(TransportError::NotFound(_))),
        "{unknown:?}"
    );
    let target = targets.recv().await.unwrap();
    let asked = Url::parse(&format!("http://{domain}{target}")).unwrap();
    assert_eq!(asked.path(), "/.well-known/webfinger");
    assert_eq!(
        asked.query_pairs().into_owned().collect::<Vec<_>>(),
        vec![("resource".to_owned(), format!("acct:da#ve&rel=x?@{domain}"))]
    );
}

/// A peer on the loopback interface answering every request with `status` and no body.
async fn a_peer_answering(status: &'static str) -> String {
    a_peer_noting(status).await.0
}

async fn resolving_dave_at(domain: &str) -> Result<(), TransportError> {
    resolve_remote_actor(
        "dave",
        domain,
        "http",
        UrlPolicy::from_issuer("http://localhost"),
    )
    .await
    .map(|_| ())
}

/// Only an instance that answers can say it knows no such account; one that fails to answer says
/// nothing of the kind.
#[tokio::test]
async fn an_unknown_account_is_told_apart_from_an_instance_that_does_not_answer() {
    let unknown = resolving_dave_at(&a_peer_answering("404 Not Found").await).await;
    let failing = resolving_dave_at(&a_peer_answering("500 Internal Server Error").await).await;
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead = closed.local_addr().unwrap().to_string();
    drop(closed);
    let unreachable = resolving_dave_at(&dead).await;

    assert!(
        matches!(unknown, Err(TransportError::NotFound(_))),
        "{unknown:?}"
    );
    assert!(
        matches!(failing, Err(TransportError::Upstream(_))),
        "{failing:?}"
    );
    assert!(
        matches!(unreachable, Err(TransportError::Upstream(_))),
        "{unreachable:?}"
    );
}

/// Serves on `listener`: the path `moved` names answers `302` to its target, any other `document`.
fn serve(listener: TcpListener, moved: (&'static str, String), document: Value) {
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let mut request = [0; 4096];
            let read = socket.read(&mut request).await.unwrap_or(0);
            let request = String::from_utf8_lossy(&request[..read]);
            let response = if request.split(' ').nth(1) == Some(moved.0) {
                format!(
                    "HTTP/1.1 302 Found\r\nlocation: {}\r\ncontent-length: 0\r\n\
                     connection: close\r\n\r\n",
                    moved.1
                )
            } else {
                let body = document.to_string();
                format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                     content-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                )
            };
            let _ = socket.write_all(response.as_bytes()).await;
        }
    });
}

#[tokio::test]
async fn a_document_another_instance_serves_through_a_redirect_is_refused() {
    let victim = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let evil = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (at, evil_at) = (victim.local_addr().unwrap(), evil.local_addr().unwrap());
    let (_, passing_off) = dave_at(&at.to_string());
    serve(evil, ("/", String::new()), passing_off);
    serve(
        victim,
        ("/users/dave", format!("http://{evil_at}/users/dave")),
        json!({}),
    );

    let refused = fetch_remote_actor(
        &format!("http://{at}/users/dave"),
        UrlPolicy::from_issuer("http://localhost"),
    )
    .await;

    assert!(
        matches!(&refused, Err(TransportError::Upstream(m)) if m.contains("off its origin")),
        "{refused:?}"
    );
}

#[tokio::test]
async fn a_document_moved_within_its_instance_is_still_read() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let at = listener.local_addr().unwrap();
    let (_, document) = dave_at(&at.to_string());
    serve(
        listener,
        ("/users/dave", "/actors/dave".to_owned()),
        document,
    );

    let dave = fetch_remote_actor(
        &format!("http://{at}/users/dave"),
        UrlPolicy::from_issuer("http://localhost"),
    )
    .await
    .unwrap();

    assert_eq!(dave.actor_url.as_str(), format!("http://{at}/users/dave"));
}
