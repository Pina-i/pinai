use domain::identity::testing::{InMemoryAccounts, account};
use domain::profile::OwnProfile;
use domain::profile::testing::{InMemoryProfiles, ProfileSeeds, own_profile};

use super::*;

#[tokio::test]
async fn a_person_shows_the_accounts_pronouns_and_bio() {
    let alice = account("alice");
    let profiles = Arc::new(InMemoryProfiles::default());
    profiles
        .sign_up(&OwnProfile {
            id: alice.id,
            pronouns: Some(Pronouns::He),
            bio: Some("kia ora".to_owned()),
            ..own_profile("alice")
        })
        .await;
    let show = ShowPerson::new(
        InstanceOrigin::parse("http://localhost:8080").unwrap(),
        Arc::new(InMemoryAccounts::with([alice.clone()])),
        profiles,
    );

    let person = show.execute("alice_t3st0").await.unwrap();

    assert_eq!(
        person,
        Some(Person {
            account: alice,
            pronouns: Some(Pronouns::He),
            bio: Some("kia ora".to_owned()),
        })
    );
    assert_eq!(show.execute("nobody_x1y2z").await.unwrap(), None);
}
