use std::sync::Arc;

use domain::UserId;
use domain::identity::{TokenError, TokenVerifier};
use jwt_utils::{EdKeyPair, issue_access_token, load_ed_keypair_from_pem};

use super::*;

const ISSUER: &str = "http://localhost:8080";
// Minted for these tests only.
const TEST_KEY: &str = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIF1VRwFuAo+gfSZtIUeF2VmNnVy0VePE+L7/D1UTTV6/
-----END PRIVATE KEY-----
";

fn keypair() -> Arc<EdKeyPair> {
    let path =
        std::env::temp_dir().join(format!("pinai-token-verifier-{}.pem", uuid::Uuid::new_v4()));
    std::fs::write(&path, TEST_KEY).unwrap();
    let keypair = load_ed_keypair_from_pem(&path, "test-key").unwrap();
    std::fs::remove_file(&path).unwrap();
    Arc::new(keypair)
}

fn token(keypair: &EdKeyPair, issuer: &str, subject: &str, ttl: i64) -> String {
    issue_access_token(
        keypair,
        issuer,
        subject,
        "web-client",
        "a@idp.test",
        "a",
        ttl,
    )
    .unwrap()
}

#[test]
fn a_token_this_instance_issued_names_its_user() {
    let keypair = keypair();
    let user = UserId::generate();
    let verifier = JwtTokenVerifier::new(keypair.clone(), ISSUER.to_owned());

    let verified = verifier.verify(&token(&keypair, ISSUER, &user.to_string(), 60));

    assert_eq!(verified.unwrap(), user);
}

#[test]
fn an_expired_or_foreign_token_is_refused() {
    let keypair = keypair();
    let verifier = JwtTokenVerifier::new(keypair.clone(), ISSUER.to_owned());
    let user = UserId::generate().to_string();

    for token in [
        token(&keypair, ISSUER, &user, -120),
        token(&keypair, "https://idp.other.test", &user, 60),
        "not-a-jwt".to_owned(),
    ] {
        assert!(matches!(verifier.verify(&token), Err(TokenError::Invalid)));
    }
    assert!(matches!(
        verifier.verify(&token(&keypair, ISSUER, "not-a-uuid", 60)),
        Err(TokenError::BadSubject)
    ));
}
