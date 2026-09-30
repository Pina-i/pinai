use std::net::SocketAddr;

use federation_transport::UrlPolicy;
use http_signatures::{SignParams, http_date_now, sha256_digest, sign_request};
use jwt_utils::load_ed_keypair_from_pem;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::*;

// Minted for these tests only.
const TEST_KEY: &str = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIF1VRwFuAo+gfSZtIUeF2VmNnVy0VePE+L7/D1UTTV6/
-----END PRIVATE KEY-----
";

fn verifier() -> HttpSignatureVerifier {
    HttpSignatureVerifier::new(Arc::new(KeyCache::new(UrlPolicy::from_issuer(
        "https://idp.alice.test",
    ))))
}

fn request(headers: &[(&str, &str)]) -> SignedRequest {
    SignedRequest {
        method: "post".into(),
        target: "/api/keys/packages/claim".into(),
        headers: headers
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect(),
        body: None,
    }
}

#[tokio::test]
async fn an_unsigned_or_garbled_request_is_malformed() {
    let unsigned = verifier().verify(&request(&[])).await;
    let garbled = verifier()
        .verify(&request(&[("signature", "not a signature")]))
        .await;

    assert!(
        matches!(&unsigned, Err(SignatureError::Malformed(reason)) if reason == "missing Signature header"),
        "{unsigned:?}"
    );
    assert!(
        matches!(garbled, Err(SignatureError::Malformed(_))),
        "{garbled:?}"
    );
}

/// A peer on the loopback interface publishing the test key in its actor document, and a
/// request to `/api/presence/batch` it signed over `signed_body`.
async fn a_peer_signing(signed_body: &[u8]) -> (SignedRequest, ActorUri) {
    let path = std::env::temp_dir().join(format!("pinai-signatures-{}.pem", uuid::Uuid::new_v4()));
    std::fs::write(&path, TEST_KEY).unwrap();
    let keypair = load_ed_keypair_from_pem(&path, "test-key").unwrap();
    std::fs::remove_file(&path).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let at: SocketAddr = listener.local_addr().unwrap();
    let actor = format!("http://{at}/actor");
    let document = serde_json::json!({
        "id": actor,
        "publicKey": { "id": format!("{actor}#main-key"), "publicKeyPem": keypair.public_key_pem },
    })
    .to_string();
    let response = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/activity+json\r\n\
         content-length: {}\r\nconnection: close\r\n\r\n{document}",
        document.len()
    );
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

    let (date, digest, key_id) = (
        http_date_now(),
        sha256_digest(signed_body),
        format!("{actor}#main-key"),
    );
    let signature = sign_request(SignParams {
        method: "post",
        path: "/api/presence/batch",
        host: "idp.alice.test",
        date: &date,
        digest: Some(&digest),
        key_id: &key_id,
        signing_key: &keypair.signing_key,
    })
    .unwrap();
    let request = SignedRequest {
        method: "post".into(),
        target: "/api/presence/batch".into(),
        headers: vec![
            ("host".into(), "idp.alice.test".into()),
            ("date".into(), date),
            ("digest".into(), digest),
            ("signature".into(), signature),
        ],
        body: Some(signed_body.to_vec()),
    };
    (request, ActorUri::parse(&actor).unwrap())
}

fn dev_verifier() -> HttpSignatureVerifier {
    HttpSignatureVerifier::new(Arc::new(KeyCache::new(UrlPolicy::from_issuer(
        "http://localhost:8080",
    ))))
}

#[tokio::test]
async fn a_body_its_signed_digest_matches_is_verified() {
    let (request, peer) = a_peer_signing(br#"{"actors":[]}"#).await;

    let verified = dev_verifier().verify(&request).await;

    assert_eq!(verified.unwrap(), peer);
}

#[tokio::test]
async fn a_body_its_signed_digest_does_not_match_is_refused() {
    let (mut request, _) = a_peer_signing(br#"{"actors":[]}"#).await;
    request.body = Some(br#"{"actors":["http://idp.alice.test/users/bob_k2m9x"]}"#.to_vec());

    let refused = dev_verifier().verify(&request).await;

    assert!(
        matches!(&refused, Err(SignatureError::Refused(reason)) if reason == "Digest does not match request body"),
        "{refused:?}"
    );
}
