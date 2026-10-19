use crate::auth::testing::web_client;

use super::*;

fn at() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap()
}

fn head() -> RefreshLink {
    RefreshLink {
        session: SessionId::generate(),
        client: web_client().id,
        rotated_at: None,
        successor_unused: false,
    }
}

fn rotated(successor_unused: bool) -> RefreshLink {
    RefreshLink {
        rotated_at: Some(at()),
        successor_unused,
        ..head()
    }
}

#[test]
fn the_head_of_a_chain_rotates() {
    assert_eq!(
        head().presented(&web_client().id, at()),
        Presentation::Rotate
    );
}

#[test]
fn a_token_rotated_within_the_grace_whose_successor_never_came_is_retried() {
    let client = web_client().id;

    assert_eq!(
        rotated(true).presented(&client, at() + Duration::seconds(5)),
        Presentation::Retry
    );
    assert_eq!(
        rotated(true).presented(&client, at() + REFRESH_GRACE),
        Presentation::Retry
    );
}

#[test]
fn a_rotated_token_presented_after_the_grace_or_after_its_successor_is_reused() {
    let client = web_client().id;

    assert_eq!(
        rotated(true).presented(&client, at() + REFRESH_GRACE + Duration::seconds(1)),
        Presentation::Reuse,
        "past the grace"
    );
    assert_eq!(
        rotated(false).presented(&client, at() + Duration::seconds(5)),
        Presentation::Reuse,
        "its successor came, and was used or replaced"
    );
}

#[test]
fn another_clients_token_is_refused_whatever_its_state() {
    let other = ClientId::parse("http://localhost:5173/other.json").unwrap();

    for link in [head(), rotated(true), rotated(false)] {
        assert_eq!(link.presented(&other, at()), Presentation::Refused);
    }
}
