use super::*;
use http::HeaderValue;

const BODY: &[u8] = br#"{"type":"Follow","actor":"https://idp.bob.com/users/bob"}"#;

/// `signature_bytes` is never inspected here — only `keyId` and `headers` are.
fn sig_header(covered: &str) -> String {
    format!(
        r#"keyId="https://idp.bob.com/users/bob#main-key",headers="{covered}",signature="AAAA""#
    )
}

fn headers(sig: Option<&str>, digest: Option<&str>) -> HeaderMap {
    let mut h = HeaderMap::new();
    if let Some(s) = sig {
        h.insert("signature", HeaderValue::from_str(s).unwrap());
    }
    if let Some(d) = digest {
        h.insert("digest", HeaderValue::from_str(d).unwrap());
    }
    h
}

const SIGNED_WITH_DIGEST: &str = "(request-target) host date digest";

#[test]
fn accepts_a_digest_that_covers_and_matches_the_body() {
    let d = http_signatures::sha256_digest(BODY);
    let h = headers(Some(&sig_header(SIGNED_WITH_DIGEST)), Some(&d));
    assert!(verify_body_digest(&h, BODY).is_ok());
}

/// Replay with a swapped body: the signature is untouched and still covers
/// `digest`, but the bytes that arrived no longer hash to it.
#[test]
fn rejects_a_body_that_does_not_match_the_digest() {
    let d = http_signatures::sha256_digest(BODY);
    let h = headers(Some(&sig_header(SIGNED_WITH_DIGEST)), Some(&d));
    assert!(verify_body_digest(&h, br#"{"type":"Follow","actor":"evil"}"#).is_err());
}

/// Digest present and correct, but outside the signed set — so an attacker
/// can rewrite body and Digest together and the signature still verifies.
#[test]
fn rejects_a_digest_the_signature_does_not_cover() {
    let d = http_signatures::sha256_digest(BODY);
    let h = headers(Some(&sig_header("(request-target) host date")), Some(&d));
    assert!(verify_body_digest(&h, BODY).is_err());
}

#[test]
fn accepts_digest_covered_under_any_casing() {
    let d = http_signatures::sha256_digest(BODY);
    let h = headers(
        Some(&sig_header("(request-target) host date Digest")),
        Some(&d),
    );
    assert!(verify_body_digest(&h, BODY).is_ok());
}

#[test]
fn rejects_a_missing_digest_header() {
    let h = headers(Some(&sig_header(SIGNED_WITH_DIGEST)), None);
    assert!(verify_body_digest(&h, BODY).is_err());
}

#[test]
fn rejects_a_missing_signature_header() {
    let d = http_signatures::sha256_digest(BODY);
    assert!(verify_body_digest(&headers(None, Some(&d)), BODY).is_err());
}
