use super::*;
use crate::identity::testing::remote_actor;

fn claimed(display_name: &str, avatar_url: &str) -> PublicProfile {
    PublicProfile {
        actor: remote_actor("carol_k2m9x@idp.carol.test").actor_uri,
        display_name: Some(display_name.to_owned()),
        avatar_url: Some(avatar_url.to_owned()),
        pronouns: Some(Pronouns::She),
        bio: Some("kia ora".to_owned()),
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

#[test]
fn a_peers_bio_within_the_bio_rules_is_kept_and_any_other_dropped() {
    let with_bio = |bio: &str| PublicProfile {
        bio: Some(bio.to_owned()),
        ..claimed("Carol", "http://idp.carol.test/c.png")
    };

    assert_eq!(
        with_bio(&"é".repeat(190)).within_limits().bio,
        Some("é".repeat(190))
    );
    for bio in [&"é".repeat(191), "", "   "] {
        let kept = with_bio(bio).within_limits();
        assert_eq!(kept.bio, None, "{bio:?}");
        assert_eq!(kept.pronouns, Some(Pronouns::She));
    }
}

#[test]
fn an_account_shows_others_its_name_avatar_pronouns_and_bio() {
    let id = crate::UserId::generate();
    let own = OwnProfile {
        id,
        username: "aroha_x1y2z".to_owned(),
        email: "aroha@idp.test".to_owned(),
        email_verified: true,
        totp_enabled: false,
        admin: false,
        actor_uri: Some(remote_actor("aroha_x1y2z@idp.test").actor_uri),
        display_name: Some("Aroha".to_owned()),
        avatar_url: Some(format!("https://idp.test/avatars/{id}.png?v=1")),
        pronouns: Some(Pronouns::She),
        bio: Some("kia ora".to_owned()),
    };

    assert_eq!(
        own.public(),
        Some(PublicProfile {
            actor: own.actor_uri.clone().unwrap(),
            display_name: own.display_name.clone(),
            avatar_url: own.avatar_url.clone(),
            pronouns: Some(Pronouns::She),
            bio: Some("kia ora".to_owned()),
        })
    );
    assert_eq!(
        OwnProfile {
            actor_uri: None,
            ..own
        }
        .public(),
        None
    );
}
