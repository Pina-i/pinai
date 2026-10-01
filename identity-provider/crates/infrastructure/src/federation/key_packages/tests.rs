use std::net::SocketAddr;

use jwt_utils::load_ed_keypair_from_pem;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

use super::*;

// Minted for these tests only.
const TEST_KEY: &str = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIF1VRwFuAo+gfSZtIUeF2VmNnVy0VePE+L7/D1UTTV6/
-----END PRIVATE KEY-----
";

fn remote(issuer: &str) -> SignedRemoteKeyPackages {
    let path = std::env::temp_dir().join(format!("pinai-claims-{}.pem", uuid::Uuid::new_v4()));
    std::fs::write(&path, TEST_KEY).unwrap();
    let keypair = load_ed_keypair_from_pem(&path, "test-key").unwrap();
    std::fs::remove_file(&path).unwrap();
    SignedRemoteKeyPackages::new(Arc::new(keypair), UrlPolicy::from_issuer(issuer))
}

/// A peer on the loopback interface that answers once with `response`, and hands back what it
/// was sent.
async fn peer(response: String) -> (SocketAddr, oneshot::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (sent, received) = oneshot::channel();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = vec![0; 8192];
        let n = socket.read(&mut request).await.unwrap();
        let _ = sent.send(String::from_utf8_lossy(&request[..n]).into_owned());
        let _ = socket.write_all(response.as_bytes()).await;
        let _ = socket.shutdown().await;
    });
    (address, received)
}

fn answer(json: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{json}",
        json.len()
    )
}

fn alice() -> ActorUri {
    ActorUri::parse("http://localhost:8080/users/alice_t3st0").unwrap()
}

#[tokio::test]
async fn a_claim_is_signed_as_the_sender_and_asked_of_the_targets_instance() {
    let device = uuid::Uuid::new_v4();
    let (address, received) = peer(answer(&format!(
        r#"{{"key_package":"AQID","device_id":"{device}","expires_at":"2026-10-06T12:00:00Z","remaining_count":7,"needs_refill":false}}"#
    )))
    .await;
    let bob = ActorUri::parse(&format!("http://{address}/users/bob_t3st0")).unwrap();

    let claim = remote("http://localhost:8080")
        .claim(&alice(), &bob, None)
        .await
        .unwrap();

    assert_eq!(
        claim,
        Claim {
            package: ClaimedKeyPackage {
                device: device.into(),
                bytes: KeyPackageBytes::parse(vec![1, 2, 3]).unwrap(),
                expires_at: OffsetDateTime::parse(
                    "2026-10-06T12:00:00Z",
                    &time::format_description::well_known::Rfc3339
                )
                .unwrap(),
            },
            remaining: 7,
            needs_refill: false,
        }
    );
    let request = received.await.unwrap();
    assert!(
        request.starts_with("POST /api/keys/packages/claim HTTP/1.1"),
        "{request}"
    );
    assert!(
        request.contains(r#"keyId="http://localhost:8080/users/alice_t3st0#main-key""#),
        "{request}"
    );
    assert!(
        request.contains(&format!(r#""actor_uri":"{bob}""#)),
        "{request}"
    );
}

#[tokio::test]
async fn a_private_address_is_never_asked_by_a_public_instance() {
    let (address, _) = peer(answer("{}")).await;
    let internal = ActorUri::parse(&format!("http://{address}/users/bob_t3st0")).unwrap();

    let refused = remote("https://idp.alice.test")
        .claim(&alice(), &internal, None)
        .await;

    assert!(
        matches!(refused, Err(RemoteClaimError::NotAllowed(_))),
        "{refused:?}"
    );
}

fn refusing(status: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

async fn claim_from(response: String) -> Result<Claim, RemoteClaimError> {
    let (address, _) = peer(response).await;
    let target = ActorUri::parse(&format!("http://{address}/users/bob_t3st0")).unwrap();
    remote("http://localhost:8080")
        .claim(&alice(), &target, None)
        .await
}

#[tokio::test]
async fn a_peers_refusal_comes_back_as_what_it_means() {
    let unknown = claim_from(refusing("404 Not Found", r#"{"error":"not_found"}"#)).await;
    let empty = claim_from(refusing("409 Conflict", r#"{"error":"conflict"}"#)).await;
    let busy = claim_from(refusing("429 Too Many Requests", "{}")).await;
    let kept_out = claim_from(refusing("403 Forbidden", r#"{"error":"access_denied"}"#)).await;

    assert!(
        matches!(unknown, Err(RemoteClaimError::UserNotFound)),
        "{unknown:?}"
    );
    assert!(
        matches!(empty, Err(RemoteClaimError::NoKeyPackage)),
        "{empty:?}"
    );
    assert!(matches!(busy, Err(RemoteClaimError::Busy)), "{busy:?}");
    assert!(
        matches!(kept_out, Err(RemoteClaimError::Unreachable)),
        "{kept_out:?}"
    );
}

#[tokio::test]
async fn a_peer_failing_otherwise_is_unavailable() {
    let failed = claim_from(refusing(
        "500 Internal Server Error",
        r#"{"detail":"hunter2"}"#,
    ))
    .await;
    let garbled = claim_from(answer("not json")).await;

    assert!(
        matches!(failed, Err(RemoteClaimError::Unavailable(_))),
        "{failed:?}"
    );
    assert!(
        matches!(garbled, Err(RemoteClaimError::Unavailable(_))),
        "{garbled:?}"
    );
}
