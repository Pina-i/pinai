use super::*;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[test]
fn classifies_private_and_public_addresses() {
    for s in [
        "127.0.0.1",
        "10.0.0.1",
        "192.168.1.1",
        "172.16.0.1",
        "169.254.1.1", // link local
        "100.64.0.1",  // carrier-grade NAT
        "0.0.0.0",
        "::1",
        "fc00::1",          // unique local
        "fe80::1",          // link local
        "::ffff:127.0.0.1", // v4-mapped loopback
    ] {
        assert!(is_private(&ip(s)), "{s} should be rejected");
    }
    for s in [
        "1.1.1.1",
        "93.184.216.34",
        "2606:4700:4700::1111",
        "100.128.0.1",
    ] {
        assert!(!is_private(&ip(s)), "{s} should be allowed");
    }
}

#[test]
fn an_https_issuer_means_production() {
    let p = UrlPolicy::from_issuer("https://idp.example.com");
    assert!(p.require_https && !p.allow_private_networks);
}

/// The alice/bob dev pair federates over http://localhost, which production
/// rules would block outright.
#[test]
fn a_plain_http_issuer_means_local_dev() {
    let p = UrlPolicy::from_issuer("http://localhost:8080");
    assert!(!p.require_https && p.allow_private_networks);
}

#[tokio::test]
async fn rejects_plaintext_peers_in_production() {
    let p = UrlPolicy {
        require_https: true,
        allow_private_networks: false,
    };
    assert!(screen_url("http://evil.example/actor", p).await.is_err());
}

#[tokio::test]
async fn rejects_non_http_schemes() {
    let p = UrlPolicy {
        require_https: false,
        allow_private_networks: true,
    };
    assert!(screen_url("file:///etc/passwd", p).await.is_err());
    assert!(screen_url("gopher://example.com/", p).await.is_err());
}

/// The SSRF case: a keyId pointing back into the deployment's own network.
#[tokio::test]
async fn rejects_peers_resolving_into_private_space() {
    let p = UrlPolicy {
        require_https: false,
        allow_private_networks: false,
    };
    assert!(screen_url("http://127.0.0.1:8080/actor", p).await.is_err());
    assert!(screen_url("http://169.254.169.254/latest/meta-data", p)
        .await
        .is_err());
}

#[tokio::test]
async fn allows_loopback_only_when_the_policy_does() {
    let p = UrlPolicy {
        require_https: false,
        allow_private_networks: true,
    };
    assert!(screen_url("http://127.0.0.1:8080/actor", p).await.is_ok());
}
