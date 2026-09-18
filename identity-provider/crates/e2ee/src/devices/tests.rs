use super::*;

#[test]
fn missing_ua_falls_back_to_web_client() {
    assert_eq!(
        parse_user_agent(None),
        ("Web client".to_string(), "unknown")
    );
    assert_eq!(
        parse_user_agent(Some("")),
        ("Web client".to_string(), "unknown")
    );
}

#[test]
fn iphone_safari() {
    let ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) \
              AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1";
    assert_eq!(
        parse_user_agent(Some(ua)),
        ("Safari on iOS".to_string(), "phone")
    );
}

#[test]
fn ipad_safari() {
    let ua = "Mozilla/5.0 (iPad; CPU OS 17_3 like Mac OS X) \
              AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1";
    assert_eq!(
        parse_user_agent(Some(ua)),
        ("Safari on iPadOS".to_string(), "tablet")
    );
}

#[test]
fn android_chrome_phone() {
    let ua = "Mozilla/5.0 (Linux; Android 14; Pixel 8) \
              AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36";
    assert_eq!(
        parse_user_agent(Some(ua)),
        ("Chrome on Android".to_string(), "phone")
    );
}

#[test]
fn android_chrome_tablet() {
    // Same UA without "Mobile" → tablet per Google's convention.
    let ua = "Mozilla/5.0 (Linux; Android 14) \
              AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36";
    assert_eq!(
        parse_user_agent(Some(ua)),
        ("Chrome on Android".to_string(), "tablet")
    );
}

#[test]
fn firefox_macos() {
    let ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:130.0) Gecko/20100101 Firefox/130.0";
    assert_eq!(
        parse_user_agent(Some(ua)),
        ("Firefox on macOS".to_string(), "laptop")
    );
}

#[test]
fn chrome_windows() {
    let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
              AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36";
    assert_eq!(
        parse_user_agent(Some(ua)),
        ("Chrome on Windows".to_string(), "laptop")
    );
}

#[test]
fn edge_wins_over_chrome() {
    let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
              AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0";
    assert_eq!(
        parse_user_agent(Some(ua)),
        ("Edge on Windows".to_string(), "laptop")
    );
}

#[test]
fn unrecognised_ua() {
    assert_eq!(
        parse_user_agent(Some("WeirdCustomBot/1.0")),
        ("Web client".to_string(), "unknown"),
    );
}
