use federation_transport::UrlPolicy;

use super::*;

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
