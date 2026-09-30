use super::*;
use crate::identity::testing::remote_actor;

fn claimed(display_name: &str, avatar_url: &str) -> PublicProfile {
    PublicProfile {
        actor: remote_actor("carol_k2m9x@idp.carol.test").actor_uri,
        display_name: Some(display_name.to_owned()),
        avatar_url: Some(avatar_url.to_owned()),
    }
}

#[test]
fn a_peers_name_and_avatar_within_the_limits_are_kept() {
    let kept = claimed("  Carol R.  ", "https://cdn.carol.test/avatars/c.png?v=3").within_limits();

    assert_eq!(kept.display_name.as_deref(), Some("Carol R."));
    assert_eq!(
        kept.avatar_url.as_deref(),
        Some("https://cdn.carol.test/avatars/c.png?v=3")
    );
}

#[test]
fn a_name_the_display_name_rules_refuse_is_dropped() {
    for name in ["", "   ", &"é".repeat(51)] {
        let kept = claimed(name, "http://idp.carol.test/c.png").within_limits();

        assert_eq!(kept.display_name, None, "{name:?}");
        assert!(kept.avatar_url.is_some());
    }
}

#[test]
fn an_avatar_anywhere_but_at_an_http_url_is_dropped() {
    let long = format!("https://cdn.carol.test/{}", "a".repeat(2048));
    for url in [
        "javascript:alert(1)",
        "data:image/png;base64,iVBORw0KGgo=",
        "file:///etc/passwd",
        "ftp://idp.carol.test/c.png",
        "not a url",
        long.as_str(),
    ] {
        let kept = claimed("Carol", url).within_limits();

        assert_eq!(kept.avatar_url, None, "{url:?}");
        assert!(kept.display_name.is_some());
    }
}
