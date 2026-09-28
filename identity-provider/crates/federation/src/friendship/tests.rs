use super::*;

use time::OffsetDateTime;
use uuid::Uuid;

const ACTOR: &str = "https://idp.bob.test/users/bob_xK9mP";

fn remote(inbox_url: Option<&str>) -> RemoteActor {
    RemoteActor {
        id: Uuid::new_v4(),
        actor_uri: ACTOR.to_string(),
        inbox_url: inbox_url.map(str::to_string),
        instance: "idp.bob.test".to_string(),
        display_name: None,
        avatar_url: None,
        fetched_at: OffsetDateTime::UNIX_EPOCH,
        updated_at: OffsetDateTime::UNIX_EPOCH,
    }
}

#[test]
fn a_cached_inbox_is_used_as_resolved() {
    let inbox = "https://idp.bob.test/inboxes/bob";
    assert_eq!(remote_inbox(&remote(Some(inbox))), inbox);
}

#[test]
fn an_actor_without_a_cached_inbox_falls_back_to_the_conventional_path() {
    assert_eq!(remote_inbox(&remote(None)), format!("{ACTOR}/inbox"));
}
