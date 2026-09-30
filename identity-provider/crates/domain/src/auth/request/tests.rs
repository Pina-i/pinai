use super::*;

// RFC 7636 appendix B.
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

#[test]
fn only_an_s256_challenge_is_accepted() {
    assert!(CodeChallenge::parse(CHALLENGE, "S256").is_ok());
    for method in ["plain", "s256", "", "S512"] {
        assert!(
            matches!(
                CodeChallenge::parse(CHALLENGE, method),
                Err(AuthError::BadChallengeMethod)
            ),
            "{method}"
        );
    }
}

#[test]
fn a_challenge_is_met_by_its_verifier_only() {
    let challenge = CodeChallenge::parse(CHALLENGE, "S256").unwrap();

    assert!(challenge.is_met_by(VERIFIER));
    assert!(!challenge.is_met_by(&VERIFIER[1..]));
    assert!(!challenge.is_met_by(CHALLENGE));
    assert!(!challenge.is_met_by(""));
}

#[test]
fn a_signup_code_is_six_digits() {
    assert!(OtpCode::parse("012345").is_ok());
    for refused in ["12345", "1234567", "12345a", "", "١٢٣٤٥٦"] {
        assert!(OtpCode::parse(refused).is_err(), "{refused}");
    }
}
