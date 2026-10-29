use std::time::Duration;

use domain::identity::testing::{account, remote_actor};
use domain::identity::{FederatedAddress, RemoteActorsError};
use domain::profile::Pronouns;
use tokio::sync::mpsc;

use super::*;

fn shown(alice: &Account) -> PublicProfile {
    PublicProfile {
        actor: alice.actor_uri.clone(),
        display_name: Some("alice".to_owned()),
        avatar_url: Some(format!(
            "http://localhost:8080/avatars/{}.png?v=1",
            alice.id
        )),
        pronouns: Some(Pronouns::NonBinary),
        bio: Some("kia ora".to_owned()),
    }
}

#[test]
fn an_update_carries_the_whole_shown_profile_as_its_person() {
    let alice = account("alice");

    let update = update_person(&alice, &shown(&alice));

    assert_eq!(update["type"], "Update");
    assert_eq!(update["actor"], alice.actor_uri.as_str());
    let person = &update["object"];
    assert_eq!(person["type"], "Person");
    assert_eq!(person["id"], alice.actor_uri.as_str());
    assert_eq!(person["preferredUsername"], alice.username.as_str());
    assert_eq!(person["name"], "alice");
    assert_eq!(
        person["icon"]["url"],
        format!("http://localhost:8080/avatars/{}.png?v=1", alice.id)
    );
    assert_eq!(person["pronouns"], "non-binary");
    assert_eq!(person["summary"], "kia ora");
}

#[test]
fn an_update_carries_nothing_of_what_the_profile_lacks() {
    let alice = account("alice");
    let bare = PublicProfile {
        display_name: None,
        avatar_url: None,
        pronouns: None,
        bio: None,
        ..shown(&alice)
    };

    let person = &update_person(&alice, &bare)["object"];

    for field in ["name", "icon", "pronouns", "summary"] {
        assert!(person.get(field).is_none(), "{field}");
    }
}

/// Tells the test each account it was asked to rediscover.
struct Rediscovering(mpsc::UnboundedSender<ActorUri>);

#[async_trait::async_trait]
impl RemoteActors for Rediscovering {
    async fn resolve(&self, _: &FederatedAddress) -> Result<RemoteActor, RemoteActorsError> {
        unreachable!("a refresh resolves nobody by address")
    }

    async fn find(&self, _: &ActorUri) -> Result<Option<RemoteActor>, RemoteActorsError> {
        unreachable!("a refresh asks the instance, not the cache")
    }

    async fn discover(&self, uri: &ActorUri) -> Result<RemoteActor, RemoteActorsError> {
        self.0.send(uri.clone()).unwrap();
        Err(RemoteActorsError::Unavailable("down".to_owned()))
    }
}

#[tokio::test]
async fn a_refresh_rediscovers_the_account_off_the_request() {
    let (asked, mut heard) = mpsc::unbounded_channel();
    let carol = remote_actor("carol_k2m9x@idp.carol.test").actor_uri;

    BackgroundProfileRefresh::new(Arc::new(Rediscovering(asked))).refresh(&carol);

    let rediscovered = tokio::time::timeout(Duration::from_secs(5), heard.recv()).await;
    assert_eq!(rediscovered.unwrap(), Some(carol));
}
