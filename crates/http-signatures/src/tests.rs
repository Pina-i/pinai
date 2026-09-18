use super::*;
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::EncodePublicKey;

const HOST: &str = "idp.bob.com";
const PATH: &str = "/users/bob/inbox";
const DATE: &str = "Thu, 18 Sep 2026 10:00:00 +0000";
const KEY_ID: &str = "https://idp.alice.com/users/alice#main-key";

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn pem_of(k: &SigningKey) -> String {
    k.verifying_key()
        .to_public_key_pem(LineEnding::LF)
        .expect("public key should encode to PEM")
}

/// A signed POST as `deliver_activity` builds it.
fn signed_post(k: &SigningKey, digest: &str) -> String {
    sign_request(SignParams {
        method: "post",
        path: PATH,
        host: HOST,
        date: DATE,
        digest: Some(digest),
        key_id: KEY_ID,
        signing_key: k,
    })
    .expect("signing should succeed")
}

/// The headers a peer would present alongside that signature.
fn headers_of(sig: &str, digest: Option<&str>) -> Vec<(String, String)> {
    let mut h = vec![
        ("host".to_string(), HOST.to_string()),
        ("date".to_string(), DATE.to_string()),
        ("signature".to_string(), sig.to_string()),
    ];
    if let Some(d) = digest {
        h.push(("digest".to_string(), d.to_string()));
    }
    h
}

fn lookup(headers: &[(String, String)]) -> impl Fn(&str) -> Option<String> + '_ {
    move |name: &str| {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
    }
}

fn verify(
    sig: &str,
    headers: &[(String, String)],
    method: &str,
    path: &str,
    k: &SigningKey,
) -> Result<(), VerifyError> {
    verify_request_with_key(method, path, sig, lookup(headers), &k.verifying_key())
}

// ─── Digest ──────────────────────────────────────────────────────────────────
// Expected values are published SHA-256 vectors, not recomputed here — a digest
// test that hashes the input the same way the code does can never disagree with it.

#[test]
fn the_digest_of_an_empty_body_matches_the_published_vector() {
    assert_eq!(
        sha256_digest(b""),
        "SHA-256=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
    );
}

#[test]
fn the_digest_of_abc_matches_the_published_vector() {
    assert_eq!(
        sha256_digest(b"abc"),
        "SHA-256=ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="
    );
}

#[test]
fn a_different_body_gives_a_different_digest() {
    assert_ne!(sha256_digest(b"abc"), sha256_digest(b"abd"));
}

// ─── Round trip ──────────────────────────────────────────────────────────────

#[test]
fn a_signed_post_verifies_with_the_signers_key() {
    let k = key(1);
    let digest = sha256_digest(br#"{"type":"Follow"}"#);
    let sig = signed_post(&k, &digest);

    assert!(verify(&sig, &headers_of(&sig, Some(&digest)), "post", PATH, &k).is_ok());
}

#[test]
fn a_signed_get_verifies_without_a_digest() {
    let k = key(1);
    let sig = sign_request(SignParams {
        method: "get",
        path: "/api/presence/stream?actors[]=alice",
        host: HOST,
        date: DATE,
        digest: None,
        key_id: KEY_ID,
        signing_key: &k,
    })
    .unwrap();

    let headers = headers_of(&sig, None);
    assert!(verify(
        &sig,
        &headers,
        "get",
        "/api/presence/stream?actors[]=alice",
        &k
    )
    .is_ok());
}

#[test]
fn the_method_is_compared_case_insensitively() {
    let k = key(1);
    let digest = sha256_digest(b"{}");
    let sig = signed_post(&k, &digest);

    // Signed as "post"; a verifier passing "POST" must still accept.
    assert!(verify(&sig, &headers_of(&sig, Some(&digest)), "POST", PATH, &k).is_ok());
}

#[test]
fn verification_accepts_a_pem_encoded_key() {
    let k = key(1);
    let digest = sha256_digest(b"{}");
    let sig = signed_post(&k, &digest);
    let headers = headers_of(&sig, Some(&digest));

    assert!(verify_request("post", PATH, &sig, lookup(&headers), &pem_of(&k)).is_ok());
}

// ─── What a signature must refuse ────────────────────────────────────────────

#[test]
fn a_signature_from_another_key_is_refused() {
    let signer = key(1);
    let impostor = key(2);
    let digest = sha256_digest(b"{}");
    let sig = signed_post(&signer, &digest);

    assert!(verify(
        &sig,
        &headers_of(&sig, Some(&digest)),
        "post",
        PATH,
        &impostor
    )
    .is_err());
}

/// Replaying a signed request at a different endpoint: the path is inside
/// `(request-target)`, so the signature must not travel.
#[test]
fn a_signature_does_not_transfer_to_another_path() {
    let k = key(1);
    let digest = sha256_digest(b"{}");
    let sig = signed_post(&k, &digest);

    assert!(verify(
        &sig,
        &headers_of(&sig, Some(&digest)),
        "post",
        "/users/carol/inbox",
        &k
    )
    .is_err());
}

#[test]
fn a_signature_does_not_transfer_to_another_method() {
    let k = key(1);
    let digest = sha256_digest(b"{}");
    let sig = signed_post(&k, &digest);

    assert!(verify(&sig, &headers_of(&sig, Some(&digest)), "get", PATH, &k).is_err());
}

#[test]
fn a_rewritten_host_header_is_refused() {
    let k = key(1);
    let digest = sha256_digest(b"{}");
    let sig = signed_post(&k, &digest);

    let mut headers = headers_of(&sig, Some(&digest));
    headers[0].1 = "idp.evil.com".to_string();
    assert!(verify(&sig, &headers, "post", PATH, &k).is_err());
}

#[test]
fn a_rewritten_date_header_is_refused() {
    let k = key(1);
    let digest = sha256_digest(b"{}");
    let sig = signed_post(&k, &digest);

    let mut headers = headers_of(&sig, Some(&digest));
    headers[1].1 = "Thu, 18 Sep 2026 11:00:00 +0000".to_string();
    assert!(verify(&sig, &headers, "post", PATH, &k).is_err());
}

/// The digest is inside the signed string, so swapping it invalidates the
/// signature. Checking the digest against the body is a separate step the
/// caller owns.
#[test]
fn a_rewritten_digest_header_is_refused() {
    let k = key(1);
    let digest = sha256_digest(b"{}");
    let sig = signed_post(&k, &digest);

    let mut headers = headers_of(&sig, Some(&digest));
    headers[3].1 = sha256_digest(br#"{"type":"Accept"}"#);
    assert!(verify(&sig, &headers, "post", PATH, &k).is_err());
}

#[test]
fn a_covered_header_that_is_absent_is_refused() {
    let k = key(1);
    let digest = sha256_digest(b"{}");
    let sig = signed_post(&k, &digest);

    // Signature covers `digest`, but the request arrives without it.
    let headers = headers_of(&sig, None);
    assert!(matches!(
        verify(&sig, &headers, "post", PATH, &k),
        Err(VerifyError::MissingHeader(h)) if h == "digest"
    ));
}

// ─── The Signature header itself ─────────────────────────────────────────────

#[test]
fn a_post_signature_declares_the_four_headers_it_covers() {
    let sig = signed_post(&key(1), "SHA-256=x");
    let parsed = parse_signature_header(&sig).unwrap();

    assert_eq!(
        parsed.headers,
        ["(request-target)", "host", "date", "digest"]
    );
    assert_eq!(parsed.key_id, KEY_ID);
}

#[test]
fn a_get_signature_declares_no_digest() {
    let sig = sign_request(SignParams {
        method: "get",
        path: PATH,
        host: HOST,
        date: DATE,
        digest: None,
        key_id: KEY_ID,
        signing_key: &key(1),
    })
    .unwrap();

    assert_eq!(
        parse_signature_header(&sig).unwrap().headers,
        ["(request-target)", "host", "date"]
    );
}

#[test]
fn a_signature_header_announces_hs2019() {
    let sig = signed_post(&key(1), "SHA-256=x");
    assert!(sig.contains(r#"algorithm="hs2019""#), "got: {sig}");
}

#[test]
fn an_ed25519_signature_is_64_bytes() {
    let sig = signed_post(&key(1), "SHA-256=x");
    assert_eq!(
        parse_signature_header(&sig).unwrap().signature_bytes.len(),
        64
    );
}

#[test]
fn parsing_refuses_a_header_with_no_key_id() {
    let missing = r#"algorithm="hs2019",headers="host date",signature="AAAA""#;
    assert!(matches!(
        parse_signature_header(missing),
        Err(VerifyError::InvalidFormat)
    ));
}

#[test]
fn parsing_refuses_a_header_with_no_covered_headers() {
    let missing = r#"keyId="k",algorithm="hs2019",signature="AAAA""#;
    assert!(matches!(
        parse_signature_header(missing),
        Err(VerifyError::InvalidFormat)
    ));
}

#[test]
fn parsing_refuses_a_header_with_no_signature() {
    let missing = r#"keyId="k",algorithm="hs2019",headers="host date""#;
    assert!(matches!(
        parse_signature_header(missing),
        Err(VerifyError::InvalidFormat)
    ));
}

#[test]
fn parsing_refuses_an_unquoted_value() {
    let unquoted = r#"keyId=k,headers="host date",signature="AAAA""#;
    assert!(parse_signature_header(unquoted).is_err());
}

#[test]
fn parsing_refuses_a_signature_that_is_not_base64() {
    let bad = r#"keyId="k",headers="host date",signature="!!!not base64!!!""#;
    assert!(matches!(
        parse_signature_header(bad),
        Err(VerifyError::Base64)
    ));
}

/// Ed25519 signatures are 64 bytes; anything else must be rejected as a bad
/// signature rather than panicking on the conversion.
#[test]
fn a_signature_of_the_wrong_length_is_refused() {
    let k = key(1);
    let short = r#"keyId="k",headers="(request-target) host date",signature="AAAA""#;
    let headers = headers_of(short, None);

    assert!(matches!(
        verify(short, &headers, "post", PATH, &k),
        Err(VerifyError::BadSignature)
    ));
}
