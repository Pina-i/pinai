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
        "224.0.0.1",        // multicast
        "239.255.255.250",
        "240.0.0.1", // reserved
        "255.255.255.255",
        "198.18.0.1", // benchmarking
        "198.19.255.255",
        "192.0.0.8",                            // IETF protocol assignments
        "0.1.2.3",                              // this network
        "::ffff:10.0.0.5",                      // v4-mapped private
        "::10.0.0.5",                           // v4-compatible private
        "64:ff9b::a00:5",                       // NAT64 of 10.0.0.5
        "64:ff9b::a9fe:a9fe",                   // NAT64 of 169.254.169.254
        "64:ff9b:1::8.8.8.8",                   // local-use NAT64
        "ff02::1",                              // multicast
        "2002:a00:5::1",                        // 6to4 of 10.0.0.5
        "2002:7f00:1::",                        // 6to4 of 127.0.0.1
        "2002:a9fe:a9fe:1::1",                  // 6to4 of 169.254.169.254
        "2001:0:4136:e378:8000:63bf:3fff:fdd2", // Teredo, its server and client public
        "2001:0:a00:5:8000:63bf:f5ff:fffa",     // Teredo, its server 10.0.0.5
        "2001::1",
        "fec0::1", // site local
        "fef0::1",
        "100::1",          // discard
        "2001:db8::1",     // documentation
        "::ffff:0:a00:5",  // SIIT of 10.0.0.5
        "::ffff:0:7f00:1", // SIIT of 127.0.0.1
    ] {
        assert!(is_private(&ip(s)), "{s} should be rejected");
    }
    for s in [
        "1.1.1.1",
        "93.184.216.34",
        "2606:4700:4700::1111",
        "100.128.0.1",
        "198.20.0.1",
        "192.0.1.1",
        "223.255.255.255",
        "::ffff:1.1.1.1",
        "64:ff9b::101:101", // NAT64 of 1.1.1.1
        "2002:101:101::1",  // 6to4 of 1.1.1.1
        "2001:4860:4860::8888",
        "::ffff:0:101:101", // SIIT of 1.1.1.1
        "100:0:0:1::1",
        "2001:db9::1",
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

#[tokio::test]
async fn an_ip_literal_is_checked_as_written_without_a_lookup() {
    let p = UrlPolicy {
        require_https: true,
        allow_private_networks: false,
    };
    for private in [
        "https://[::1]/actor",
        "https://[fe80::1]/actor",
        "https://[::ffff:10.0.0.5]/actor",
        "https://[64:ff9b::a9fe:a9fe]/latest/meta-data",
        "https://[2002:a9fe:a9fe::1]/latest/meta-data",
        "https://[2001:0:a00:5:8000:63bf:f5ff:fffa]/actor",
    ] {
        let refused = screen_url(private, p).await;

        assert!(
            matches!(&refused, Err(TransportError::Denied(m)) if m.contains("private address space")),
            "{private}: {refused:?}"
        );
    }
    assert!(screen_url("https://[2606:4700:4700::1111]/actor", p)
        .await
        .is_ok());
}

const PRODUCTION: UrlPolicy = UrlPolicy {
    require_https: true,
    allow_private_networks: false,
};

const DEVELOPMENT: UrlPolicy = UrlPolicy {
    require_https: false,
    allow_private_networks: true,
};

async fn redirected(
    from: &str,
    location: &str,
    policy: UrlPolicy,
) -> Result<String, TransportError> {
    let location = reqwest::header::HeaderValue::from_str(location).unwrap();
    redirect_target(&from.parse().unwrap(), Some(&location), policy)
        .await
        .map(String::from)
}

fn refused_for(refused: &Result<String, TransportError>, reason: &str) -> bool {
    matches!(refused, Err(TransportError::Upstream(m)) if m.contains(reason))
}

#[tokio::test]
async fn a_redirect_into_private_space_is_refused_in_production() {
    for (from, location) in [
        ("https://169.254.169.254/x", "/latest/meta-data"),
        ("https://10.0.0.5:6379/x", "/"),
        ("https://127.0.0.1/users/dave", "/actors/dave"),
        ("https://[::1]/users/dave", "/actors/dave"),
    ] {
        let refused = redirected(from, location, PRODUCTION).await;

        assert!(
            refused_for(&refused, "private address space"),
            "{from} {location}: {refused:?}"
        );
    }
}

#[tokio::test]
async fn a_redirect_to_plaintext_is_refused_in_production() {
    let refused = redirected(
        "https://1.1.1.1/users/dave",
        "http://1.1.1.1/users/dave",
        PRODUCTION,
    )
    .await;

    assert!(refused_for(&refused, "off its origin"), "{refused:?}");
}

#[tokio::test]
async fn a_redirect_stays_on_the_origin_asked() {
    let from = "https://1.1.1.1/users/dave";

    assert_eq!(
        redirected(from, "/actors/dave", PRODUCTION).await.unwrap(),
        "https://1.1.1.1/actors/dave"
    );
    assert_eq!(
        redirected(from, "https://1.1.1.1:443/actors/dave", PRODUCTION)
            .await
            .unwrap(),
        "https://1.1.1.1/actors/dave"
    );
    for elsewhere in [
        "https://8.8.8.8/users/dave",
        "https://1.1.1.1:8443/users/dave",
        "//8.8.8.8/users/dave",
    ] {
        let refused = redirected(from, elsewhere, PRODUCTION).await;

        assert!(
            refused_for(&refused, "off its origin"),
            "{elsewhere}: {refused:?}"
        );
    }
}

#[tokio::test]
async fn a_redirect_without_a_target_says_what_it_lacks() {
    let from: url::Url = "http://127.0.0.1:8080/users/dave".parse().unwrap();
    let not_ascii = reqwest::header::HeaderValue::from_bytes("/caf\u{e9}".as_bytes()).unwrap();

    let without = redirect_target(&from, None, DEVELOPMENT).await;
    let unreadable = redirect_target(&from, Some(&not_ascii), DEVELOPMENT).await;

    assert!(
        matches!(&without, Err(TransportError::Upstream(m)) if m.contains("without a Location")),
        "{without:?}"
    );
    assert!(
        matches!(&unreadable, Err(TransportError::Upstream(m)) if m.contains("non-ASCII")),
        "{unreadable:?}"
    );
}

/// A peer on the loopback interface answering each request after `delay`: a path `redirects`
/// lists with its status and `Location`, any other with `{"at":<path>}`; every path asked is sent
/// to the receiver.
async fn a_redirecting_peer_after(
    delay: Duration,
    redirects: impl FnOnce(&str) -> Vec<(&'static str, &'static str, String)>,
) -> (String, tokio::sync::mpsc::UnboundedReceiver<String>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let at = listener.local_addr().unwrap().to_string();
    let redirects = redirects(&at);
    let (asked, paths) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let mut request = [0; 4096];
            let read = socket.read(&mut request).await.unwrap_or(0);
            let request = String::from_utf8_lossy(&request[..read]);
            let path = request.split(' ').nth(1).unwrap_or_default().to_owned();
            let _ = asked.send(path.clone());
            let response = match redirects.iter().find(|(from, _, _)| *from == path) {
                Some((_, status, location)) => format!(
                    "HTTP/1.1 {status}\r\nlocation: {location}\r\ncontent-length: 0\r\n\
                     connection: close\r\n\r\n"
                ),
                None => {
                    let body = serde_json::json!({ "at": path }).to_string();
                    format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                         content-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    )
                }
            };
            tokio::time::sleep(delay).await;
            let _ = socket.write_all(response.as_bytes()).await;
        }
    });
    (at, paths)
}

async fn a_redirecting_peer(
    redirects: impl FnOnce(&str) -> Vec<(&'static str, &'static str, String)>,
) -> (String, tokio::sync::mpsc::UnboundedReceiver<String>) {
    a_redirecting_peer_after(Duration::ZERO, redirects).await
}

fn asked(paths: &mut tokio::sync::mpsc::UnboundedReceiver<String>) -> Vec<String> {
    std::iter::from_fn(|| paths.try_recv().ok()).collect()
}

#[tokio::test]
async fn two_redirects_the_policy_allows_are_followed() {
    let (at, mut paths) = a_redirecting_peer(|at| {
        vec![
            ("/a", "302 Found", "/b".to_owned()),
            ("/b", "308 Permanent Redirect", format!("http://{at}/c")),
        ]
    })
    .await;

    let answer = get_json_screened(&format!("http://{at}/a"), "application/json", DEVELOPMENT)
        .await
        .unwrap();

    assert_eq!(answer, serde_json::json!({ "at": "/c" }));
    assert_eq!(asked(&mut paths), ["/a", "/b", "/c"]);
}

#[tokio::test]
async fn a_third_redirect_is_not_followed() {
    let (at, mut paths) = a_redirecting_peer(|_| {
        vec![
            ("/a", "302 Found", "/b".to_owned()),
            ("/b", "302 Found", "/c".to_owned()),
            ("/c", "307 Temporary Redirect", "/d".to_owned()),
        ]
    })
    .await;

    let refused =
        get_json_screened(&format!("http://{at}/a"), "application/json", DEVELOPMENT).await;

    assert!(
        matches!(&refused, Err(TransportError::Upstream(m)) if m.contains("more than 2 times")),
        "{refused:?}"
    );
    assert_eq!(asked(&mut paths), ["/a", "/b", "/c"]);
}

#[tokio::test]
async fn a_redirect_to_another_origin_is_not_asked() {
    let (elsewhere, mut elsewhere_paths) = a_redirecting_peer(|_| vec![]).await;
    let (at, mut paths) =
        a_redirecting_peer(|_| vec![("/a", "302 Found", format!("http://{elsewhere}/a"))]).await;

    let refused =
        get_json_screened(&format!("http://{at}/a"), "application/json", DEVELOPMENT).await;

    assert!(
        matches!(&refused, Err(TransportError::Upstream(m)) if m.contains("off its origin")),
        "{refused:?}"
    );
    assert_eq!(asked(&mut paths), ["/a"]);
    assert!(asked(&mut elsewhere_paths).is_empty());
}

#[tokio::test]
async fn a_redirect_to_another_scheme_is_not_asked() {
    let (at, mut paths) =
        a_redirecting_peer(|at| vec![("/a", "302 Found", format!("ftp://{at}/b"))]).await;

    let refused =
        get_json_screened(&format!("http://{at}/a"), "application/json", DEVELOPMENT).await;

    assert!(
        matches!(&refused, Err(TransportError::Upstream(m)) if m.contains("off its origin")),
        "{refused:?}"
    );
    assert_eq!(asked(&mut paths), ["/a"]);
}

#[tokio::test]
async fn one_deadline_covers_every_redirect() {
    let (at, _) = a_redirecting_peer_after(Duration::from_millis(150), |_| {
        vec![
            ("/a", "302 Found", "/b".to_owned()),
            ("/b", "302 Found", "/c".to_owned()),
        ]
    })
    .await;

    let late = get_json_within(
        &format!("http://{at}/a"),
        "application/json",
        DEVELOPMENT,
        Duration::from_millis(300),
    )
    .await;

    assert!(
        matches!(&late, Err(TransportError::Upstream(m)) if m.contains("took more than")),
        "{late:?}"
    );
}

#[tokio::test]
async fn one_deadline_covers_the_body() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let at = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let _ = socket.read(&mut [0; 4096]).await;
            let head = "HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{";
            let _ = socket.write_all(head.as_bytes()).await;
            tokio::time::sleep(Duration::from_millis(600)).await;
            let _ = socket.write_all(b"}").await;
        }
    });

    let late = get_json_within(
        &format!("http://{at}/a"),
        "application/json",
        DEVELOPMENT,
        Duration::from_millis(300),
    )
    .await;

    assert!(
        matches!(&late, Err(TransportError::Upstream(m)) if m.contains("took more than")),
        "{late:?}"
    );
}

/// A peer on the loopback interface answering every request `200` with a body one byte past the
/// cap — announced in `Content-Length`, or streamed without it.
async fn an_oversized_peer(announced: bool) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let at = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let _ = socket.read(&mut [0; 4096]).await;
            let length = if announced {
                format!("content-length: {}\r\n", MAX_BODY_BYTES + 1)
            } else {
                String::new()
            };
            let head = format!("HTTP/1.1 200 OK\r\n{length}connection: close\r\n\r\n");
            let _ = socket.write_all(head.as_bytes()).await;
            let _ = socket.write_all(&vec![b' '; MAX_BODY_BYTES + 1]).await;
        }
    });
    format!("http://{at}/.well-known/webfinger")
}

#[tokio::test]
async fn an_answer_past_the_body_cap_is_a_peer_failing_not_a_refusal() {
    for announced in [true, false] {
        let url = an_oversized_peer(announced).await;

        let oversized = get_json_screened(&url, "application/json", DEVELOPMENT).await;

        assert!(
            matches!(&oversized, Err(TransportError::Upstream(m)) if m.contains("byte cap")),
            "announced {announced}: {oversized:?}"
        );
    }
}

#[tokio::test]
async fn the_shared_client_follows_no_redirect_itself() {
    let (at, mut paths) = a_redirecting_peer(|_| vec![("/a", "302 Found", "/b".to_owned())]).await;

    let answer = client().get(format!("http://{at}/a")).send().await.unwrap();

    assert_eq!(answer.status(), reqwest::StatusCode::FOUND);
    assert_eq!(asked(&mut paths), ["/a"]);
}
