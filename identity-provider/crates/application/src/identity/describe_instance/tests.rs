use domain::identity::InstanceOrigin;
use domain::identity::testing::{InMemoryAccounts, account};

use super::*;

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap()
}

#[tokio::test]
async fn an_instance_is_described_by_its_intro_and_its_accounts() {
    let origin = InstanceOrigin::parse("http://localhost:8080").unwrap();
    let intro = InstanceIntro::new(&origin, Some("Aotearoa"), Some("Design people.")).unwrap();
    let accounts = Arc::new(InMemoryAccounts::with([account("alice"), account("bob")]));

    let facts = DescribeInstance::new(intro, Registrations::Open, accounts)
        .execute(now())
        .await
        .unwrap();

    assert_eq!(
        facts,
        InstanceFacts {
            name: "Aotearoa".to_owned(),
            description: Some("Design people.".to_owned()),
            people: 2,
            open_registrations: true,
        }
    );
}

#[tokio::test]
async fn the_accounts_are_counted_again_a_minute_on() {
    let origin = InstanceOrigin::parse("http://localhost:8080").unwrap();
    let accounts = Arc::new(InMemoryAccounts::with([account("alice")]));
    let describe = DescribeInstance::new(
        InstanceIntro::new(&origin, None, None).unwrap(),
        Registrations::Open,
        accounts.clone(),
    );

    describe.execute(now()).await.unwrap();
    accounts.add(account("bob"));
    let soon = describe
        .execute(now() + Duration::seconds(59))
        .await
        .unwrap();
    let later = describe
        .execute(now() + DescribeInstance::COUNT_KEPT)
        .await
        .unwrap();

    assert_eq!((soon.people, later.people), (1, 2));
}

#[tokio::test]
async fn an_instance_says_whether_its_registrations_are_open() {
    let origin = InstanceOrigin::parse("http://localhost:8080").unwrap();
    let described = async |registrations| {
        DescribeInstance::new(
            InstanceIntro::new(&origin, None, None).unwrap(),
            registrations,
            Arc::new(InMemoryAccounts::default()),
        )
        .execute(now())
        .await
        .unwrap()
        .open_registrations
    };

    assert!(described(Registrations::Open).await);
    assert!(!described(Registrations::Invite).await);
}
