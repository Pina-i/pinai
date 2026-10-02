use time::{Duration, OffsetDateTime};

use super::*;
use crate::identity::testing::remote_actor;

fn facts(local: bool, known: bool) -> CardFacts {
    CardFacts {
        profile: PublicProfile {
            actor: remote_actor("carol_k2m9x@idp.carol.test").actor_uri,
            display_name: Some("Carol".to_owned()),
            avatar_url: None,
            pronouns: None,
            bio: Some("kia ora".to_owned()),
        },
        local,
        known,
        friends_since: known.then(OffsetDateTime::now_utc),
        fetched_at: (!local).then(OffsetDateTime::now_utc),
    }
}

#[test]
fn an_account_here_is_shown_to_every_viewer() {
    let card = facts(true, false).card().expect("shown");

    assert_eq!(card.profile.bio.as_deref(), Some("kia ora"));
    assert_eq!(card.friends_since, None);
}

#[test]
fn another_instances_account_is_shown_only_to_a_viewer_who_knows_it() {
    let known = facts(false, true);

    assert_eq!(
        known.clone().card(),
        Some(ProfileCard {
            profile: known.profile.clone(),
            friends_since: known.friends_since,
        })
    );
    assert_eq!(facts(false, false).card(), None);
}

#[test]
fn a_cached_profile_goes_stale_a_day_after_it_was_heard() {
    let now = OffsetDateTime::now_utc();
    let heard = |ago: Duration| CardFacts {
        fetched_at: Some(now - ago),
        ..facts(false, true)
    };

    assert!(!heard(Duration::hours(23)).is_stale(now));
    assert!(heard(Duration::hours(25)).is_stale(now));
    assert!(
        !facts(true, false).is_stale(now),
        "an account here is never fetched"
    );
}
