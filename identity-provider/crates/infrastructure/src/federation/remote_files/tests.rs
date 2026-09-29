use std::net::SocketAddr;
use std::sync::Arc;

use domain::messaging::testing::collect;
use federation_transport::UrlPolicy;
use jwt_utils::{EdKeyPair, load_ed_keypair_from_pem};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::*;

// Minted for these tests only.
const TEST_KEY: &str = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIF1VRwFuAo+gfSZtIUeF2VmNnVy0VePE+L7/D1UTTV6/
-----END PRIVATE KEY-----
";

const SECRET: &str = "HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nsecret";

fn keypair() -> Arc<EdKeyPair> {
    let path =
        std::env::temp_dir().join(format!("pinai-remote-files-{}.pem", uuid::Uuid::new_v4()));
    std::fs::write(&path, TEST_KEY).unwrap();
    let keypair = load_ed_keypair_from_pem(&path, "test-key").unwrap();
    std::fs::remove_file(&path).unwrap();
    Arc::new(keypair)
}

/// A server on the loopback interface answering every request with `response`.
async fn serve(response: String) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let response = response.clone();
            tokio::spawn(async move {
                let mut request = [0; 4096];
                let _ = socket.read(&mut request).await;
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.shutdown().await;
            });
        }
    });
    address
}

fn content_url(at: SocketAddr) -> String {
    format!(
        "http://{at}/api/attachments/{}/content",
        uuid::Uuid::new_v4()
    )
}

fn files(issuer: &str) -> SignedRemoteFiles {
    SignedRemoteFiles::new(keypair(), issuer.to_owned(), UrlPolicy::from_issuer(issuer))
}

#[tokio::test]
async fn a_peers_file_is_fetched() {
    let peer = serve(SECRET.to_owned()).await;

    let fetched = files("http://localhost:8080")
        .fetch(&content_url(peer))
        .await;

    assert_eq!(collect(fetched.unwrap()).await.unwrap(), b"secret");
}

#[tokio::test]
async fn a_private_address_is_never_fetched_for_a_public_instance() {
    let internal = serve(SECRET.to_owned()).await;

    let fetched = files("https://idp.alice.test")
        .fetch(&content_url(internal))
        .await;

    assert!(fetched.is_err(), "fetched an internal address");
}

#[tokio::test]
async fn a_redirect_is_never_followed() {
    let internal = serve(SECRET.to_owned()).await;
    let redirecting = serve(format!(
        "HTTP/1.1 302 Found\r\nLocation: http://{internal}/secret\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    ))
    .await;

    // A development instance may reach private addresses: only the redirect is at stake here.
    let fetched = files("http://localhost:8080")
        .fetch(&content_url(redirecting))
        .await;

    assert!(fetched.is_err(), "followed the redirect");
}
