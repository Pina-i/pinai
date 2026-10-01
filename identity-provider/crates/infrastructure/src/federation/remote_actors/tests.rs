use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::*;

/// A peer on the loopback interface that answers every request with `response`.
async fn peer(response: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let mut request = vec![0; 8192];
            let _ = socket.read(&mut request).await;
            let _ = socket.write_all(response.as_bytes()).await;
            let _ = socket.shutdown().await;
        }
    });
    address
}

fn actors() -> FederatedRemoteActors {
    // Never reached: a refused resolution stops before anything is remembered.
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://nobody@127.0.0.1:1/none")
        .unwrap();
    FederatedRemoteActors::new(
        pool,
        "http".to_owned(),
        UrlPolicy::from_issuer("http://localhost:8080"),
    )
}

#[tokio::test]
async fn an_instance_answering_webfinger_with_junk_is_unavailable() {
    let address = peer(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
    )
    .await;
    let dave = FederatedAddress::parse(&format!("dave_k2m9x@{address}")).unwrap();

    let refused = actors().resolve(&dave).await;

    assert!(
        matches!(refused, Err(RemoteActorsError::Unavailable(_))),
        "{refused:?}"
    );
}

#[tokio::test]
async fn an_instance_that_does_not_know_the_account_says_so() {
    let address =
        peer("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
    let dave = FederatedAddress::parse(&format!("dave_k2m9x@{address}")).unwrap();

    let refused = actors().resolve(&dave).await;

    assert!(
        matches!(refused, Err(RemoteActorsError::NotFound)),
        "{refused:?}"
    );
}
