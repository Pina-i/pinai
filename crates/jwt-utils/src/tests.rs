use super::*;
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::SigningKey;
use std::path::PathBuf;

const ISSUER: &str = "https://idp.alice.com";
const AUDIENCE: &str = "web-client";
const SUBJECT: &str = "3f1b8a2c-0000-4000-8000-000000000001";
const EMAIL: &str = "alice@example.com";
const USERNAME: &str = "alice-7G4K";

/// A PEM on disk that removes itself, so `load_ed_keypair_from_pem` is
/// exercised through its real interface rather than around it.
struct TempPem(PathBuf);

impl TempPem {
    fn write(name: &str, contents: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("pinai-jwt-{name}-{}.pem", std::process::id()));
        std::fs::write(&path, contents).expect("temp PEM should be writable");
        Self(path)
    }
}

impl Drop for TempPem {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn pkcs8_pem(seed: u8) -> String {
    SigningKey::from_bytes(&[seed; 32])
        .to_pkcs8_pem(LineEnding::LF)
        .expect("key should encode to PKCS#8")
        .to_string()
}

fn keypair(name: &str, seed: u8) -> (EdKeyPair, TempPem) {
    let pem = TempPem::write(name, &pkcs8_pem(seed));
    let kp = load_ed_keypair_from_pem(&pem.0, "key-2026-01").expect("PEM should load");
    (kp, pem)
}

fn access_token(kp: &EdKeyPair, ttl: i64) -> String {
    issue_access_token(kp, ISSUER, SUBJECT, AUDIENCE, EMAIL, USERNAME, ttl)
        .expect("issuing should succeed")
}

// ─── Loading a key ───────────────────────────────────────────────────────────

#[test]
fn a_pkcs8_pem_loads_into_a_usable_keypair() {
    let (kp, _pem) = keypair("load", 1);

    assert_eq!(kp.kid, "key-2026-01");
    assert!(kp.public_key_pem.starts_with("-----BEGIN PUBLIC KEY-----"));
    assert_eq!(kp.verifying_key_bytes.len(), 32);
}

/// Instance keys are minted by `openssl genpkey -algorithm ed25519` — in the
/// Makefile for the host workflow, and in the `idp-keygen` compose service for
/// `docker compose up`. Nothing else pins that output to what this loader
/// accepts, so pin it here. Skipped where openssl is unavailable.
#[test]
fn an_openssl_generated_key_loads() {
    let pem = match std::process::Command::new("openssl")
        .args(["genpkey", "-algorithm", "ed25519"])
        .output()
    {
        Ok(out) if out.status.success() => String::from_utf8(out.stdout).expect("PEM is UTF-8"),
        _ => return,
    };

    let file = TempPem::write("openssl", &pem);
    let kp = load_ed_keypair_from_pem(&file.0, "openssl-key")
        .expect("openssl emits PKCS#8 PEM, which the loader must accept");

    assert_eq!(kp.verifying_key_bytes.len(), 32);
}

/// The loader derives the public key rather than being handed one; check it
/// against the key independently derived from the same seed.
#[test]
fn the_derived_public_key_belongs_to_the_private_key() {
    let (kp, _pem) = keypair("derive", 1);
    let expected = SigningKey::from_bytes(&[1u8; 32])
        .verifying_key()
        .to_bytes();

    assert_eq!(kp.verifying_key_bytes, expected);
}

#[test]
fn loading_a_missing_file_fails() {
    let missing = std::env::temp_dir().join("pinai-jwt-does-not-exist.pem");
    assert!(matches!(
        load_ed_keypair_from_pem(&missing, "k"),
        Err(JwtUtilsError::Key(_))
    ));
}

#[test]
fn loading_something_that_is_not_a_pem_fails() {
    let pem = TempPem::write("garbage", "this is not a PEM file");
    assert!(matches!(
        load_ed_keypair_from_pem(&pem.0, "k"),
        Err(JwtUtilsError::Key(_))
    ));
}

/// A public key where a private key is expected must not load.
#[test]
fn loading_a_public_key_where_a_private_key_belongs_fails() {
    use ed25519_dalek::pkcs8::EncodePublicKey;
    let public = SigningKey::from_bytes(&[1u8; 32])
        .verifying_key()
        .to_public_key_pem(LineEnding::LF)
        .unwrap();
    let pem = TempPem::write("public", &public);

    assert!(load_ed_keypair_from_pem(&pem.0, "k").is_err());
}

// ─── Issuing and validating ──────────────────────────────────────────────────

#[test]
fn an_issued_access_token_validates_and_carries_its_claims() {
    let (kp, _pem) = keypair("roundtrip", 1);
    let token = access_token(&kp, 300);

    let claims = validate_access_token(&token, &kp, ISSUER, AUDIENCE).expect("should validate");

    assert_eq!(claims.sub, SUBJECT);
    assert_eq!(claims.iss, ISSUER);
    assert_eq!(claims.aud, AUDIENCE);
    assert_eq!(claims.email, EMAIL);
    assert_eq!(claims.preferred_username, USERNAME);
    assert_eq!(claims.exp - claims.iat, 300);
}

/// The JWKS endpoint publishes keys by `kid`; a token that did not name one
/// could not be routed to the right key during rotation.
#[test]
fn an_issued_token_names_the_key_that_signed_it() {
    let (kp, _pem) = keypair("kid", 1);
    let token = access_token(&kp, 300);

    let header = jsonwebtoken::decode_header(&token).expect("header should parse");
    assert_eq!(header.kid.as_deref(), Some("key-2026-01"));
    assert_eq!(header.alg, jsonwebtoken::Algorithm::EdDSA);
}

#[test]
fn a_token_signed_by_another_key_is_refused() {
    let (signer, _p1) = keypair("signer", 1);
    let (other, _p2) = keypair("other", 2);
    let token = access_token(&signer, 300);

    assert!(validate_access_token(&token, &other, ISSUER, AUDIENCE).is_err());
}

#[test]
fn an_expired_token_is_refused() {
    let (kp, _pem) = keypair("expired", 1);
    let token = access_token(&kp, -60);

    assert!(validate_access_token(&token, &kp, ISSUER, AUDIENCE).is_err());
}

#[test]
fn a_token_minted_for_another_audience_is_refused() {
    let (kp, _pem) = keypair("aud", 1);
    let token = access_token(&kp, 300);

    assert!(validate_access_token(&token, &kp, ISSUER, "some-other-client").is_err());
}

#[test]
fn a_token_from_another_issuer_is_refused() {
    let (kp, _pem) = keypair("iss", 1);
    let token = access_token(&kp, 300);

    assert!(validate_access_token(&token, &kp, "https://idp.evil.com", AUDIENCE).is_err());
}

#[test]
fn a_token_whose_payload_was_edited_is_refused() {
    let (kp, _pem) = keypair("tamper", 1);
    let token = access_token(&kp, 300);

    let mut parts: Vec<&str> = token.split('.').collect();
    let forged = base64_url("{\"iss\":\"https://idp.alice.com\",\"sub\":\"attacker\",\"aud\":\"web-client\",\"exp\":9999999999,\"iat\":1,\"email\":\"e\",\"preferred_username\":\"u\"}");
    parts[1] = &forged;

    assert!(validate_access_token(&parts.join("."), &kp, ISSUER, AUDIENCE).is_err());
}

#[test]
fn a_structurally_invalid_token_is_refused() {
    let (kp, _pem) = keypair("garbage-token", 1);
    for bad in ["", "not-a-token", "a.b", "a.b.c.d"] {
        assert!(
            validate_access_token(bad, &kp, ISSUER, AUDIENCE).is_err(),
            "{bad:?} should not validate"
        );
    }
}

// ─── ID tokens ───────────────────────────────────────────────────────────────

#[test]
fn an_id_token_carries_the_nonce_it_was_issued_with() {
    let (kp, _pem) = keypair("nonce", 1);
    let token = issue_id_token(
        &kp,
        ISSUER,
        SUBJECT,
        AUDIENCE,
        EMAIL,
        USERNAME,
        Some("n-0S6_WzA2Mj".to_string()),
        300,
    )
    .unwrap();

    assert_eq!(
        decode_payload(&token)["nonce"].as_str(),
        Some("n-0S6_WzA2Mj")
    );
}

/// OIDC treats an absent nonce and a null nonce differently, so the field is
/// omitted rather than serialised as null.
#[test]
fn an_id_token_without_a_nonce_omits_the_field() {
    let (kp, _pem) = keypair("no-nonce", 1);
    let token = issue_id_token(&kp, ISSUER, SUBJECT, AUDIENCE, EMAIL, USERNAME, None, 300).unwrap();

    assert!(decode_payload(&token).get("nonce").is_none());
}

// ─── PKCE ────────────────────────────────────────────────────────────────────

/// RFC 7636 Appendix B publishes this verifier/challenge pair. Using it rather
/// than a locally computed value means the test can disagree with the code.
const RFC7636_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const RFC7636_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

#[test]
fn the_rfc_7636_verifier_produces_the_published_challenge() {
    assert_eq!(compute_code_challenge(RFC7636_VERIFIER), RFC7636_CHALLENGE);
}

#[test]
fn a_verifier_matching_the_stored_challenge_passes() {
    assert!(verify_pkce(RFC7636_VERIFIER, RFC7636_CHALLENGE).is_ok());
}

#[test]
fn a_verifier_that_does_not_match_is_refused() {
    assert!(matches!(
        verify_pkce("some-other-verifier", RFC7636_CHALLENGE),
        Err(JwtUtilsError::PkceVerificationFailed)
    ));
}

/// An empty verifier hashes to something; it must not be treated as a wildcard.
#[test]
fn an_empty_verifier_is_refused() {
    assert!(verify_pkce("", RFC7636_CHALLENGE).is_err());
}

#[test]
fn the_challenge_is_unpadded_base64url() {
    let challenge = compute_code_challenge(RFC7636_VERIFIER);
    assert!(!challenge.contains('='), "padding: {challenge}");
    assert!(
        !challenge.contains('+') && !challenge.contains('/'),
        "not url-safe: {challenge}"
    );
}

#[test]
fn a_generated_verifier_meets_rfc_7636_length_and_charset() {
    let v = generate_code_verifier();
    assert_eq!(v.len(), 64);
    assert!((43..=128).contains(&v.len()));
    assert!(
        v.chars().all(|c| c.is_ascii_alphanumeric()),
        "unreserved characters only: {v}"
    );
}

#[test]
fn generated_verifiers_are_not_repeated() {
    assert_ne!(generate_code_verifier(), generate_code_verifier());
}

#[test]
fn a_generated_verifier_round_trips_through_its_own_challenge() {
    let v = generate_code_verifier();
    assert!(verify_pkce(&v, &compute_code_challenge(&v)).is_ok());
}

// ─── JWKS ────────────────────────────────────────────────────────────────────

#[test]
fn the_jwks_advertises_one_ed25519_signing_key() {
    let (kp, _pem) = keypair("jwks", 1);
    let set = serde_json::to_value(JwkSet::from_keypairs(&[&kp])).unwrap();
    let jwk = &set["keys"][0];

    assert_eq!(jwk["kty"], "OKP");
    assert_eq!(jwk["crv"], "Ed25519");
    assert_eq!(jwk["alg"], "EdDSA");
    assert_eq!(jwk["kid"], "key-2026-01");
}

/// `use` is a Rust keyword, so the field is renamed on the way out — if that
/// rename is lost the JWKS stops being RFC 7517 conformant.
#[test]
fn the_jwks_key_is_published_for_signature_use() {
    let (kp, _pem) = keypair("jwks-use", 1);
    let set = serde_json::to_value(JwkSet::from_keypairs(&[&kp])).unwrap();

    assert_eq!(set["keys"][0]["use"], "sig");
}

/// RFC 8037 §2: `x` is the base64url-encoded public key, without padding.
#[test]
fn the_jwk_x_value_is_the_unpadded_public_key() {
    let (kp, _pem) = keypair("jwks-x", 1);
    let set = serde_json::to_value(JwkSet::from_keypairs(&[&kp])).unwrap();
    let x = set["keys"][0]["x"].as_str().unwrap().to_string();

    assert!(!x.contains('='), "padding: {x}");
    // 32 raw bytes encode to 43 base64url characters unpadded.
    assert_eq!(x.len(), 43);
}

/// During rotation the old key stays published for at least one token lifetime.
#[test]
fn a_rotated_keyset_publishes_both_keys() {
    let pem_a = TempPem::write("rot-a", &pkcs8_pem(1));
    let pem_b = TempPem::write("rot-b", &pkcs8_pem(2));
    let old = load_ed_keypair_from_pem(&pem_a.0, "key-2025-01").unwrap();
    let new = load_ed_keypair_from_pem(&pem_b.0, "key-2026-01").unwrap();

    let set = serde_json::to_value(JwkSet::from_keypairs(&[&new, &old])).unwrap();
    let kids: Vec<&str> = set["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["kid"].as_str().unwrap())
        .collect();

    assert_eq!(kids, ["key-2026-01", "key-2025-01"]);
    assert_ne!(set["keys"][0]["x"], set["keys"][1]["x"]);
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn base64_url(s: &str) -> String {
    use base64ct::{Base64UrlUnpadded, Encoding};
    Base64UrlUnpadded::encode_string(s.as_bytes())
}

fn decode_payload(token: &str) -> serde_json::Value {
    use base64ct::{Base64UrlUnpadded, Encoding};
    let payload = token
        .split('.')
        .nth(1)
        .expect("token should have a payload");
    let bytes = Base64UrlUnpadded::decode_vec(payload).expect("payload should be base64url");
    serde_json::from_slice(&bytes).expect("payload should be JSON")
}
