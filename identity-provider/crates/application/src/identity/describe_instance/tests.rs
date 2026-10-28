use domain::identity::testing::{InMemoryAccounts, account};
use domain::identity::{InstanceOrigin, IntroText, PINAI_SOURCE_URL};

use super::*;

fn pinai() -> SourceUrl {
    SourceUrl::parse(PINAI_SOURCE_URL).unwrap()
}

fn intro(name: Option<&str>, description: Option<&str>) -> Arc<IntroInForce> {
    let origin = InstanceOrigin::parse("http://localhost:8080").unwrap();
    Arc::new(IntroInForce::new(
        origin,
        IntroText::parse(name, description).unwrap(),
    ))
}

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap()
}

#[tokio::test]
async fn an_instance_is_described_by_its_intro_its_source_and_its_accounts() {
    let intro = intro(Some("Aotearoa"), Some("Design people."));
    let source = SourceUrl::parse("https://codeberg.org/aotearoa/pinai").unwrap();
    let accounts = Arc::new(InMemoryAccounts::with([account("alice"), account("bob")]));

    let facts = DescribeInstance::new(intro, source.clone(), Registrations::Open, accounts)
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
            source,
        }
    );
}

#[tokio::test]
async fn the_accounts_are_counted_again_a_minute_on() {
    let accounts = Arc::new(InMemoryAccounts::with([account("alice")]));
    let describe = DescribeInstance::new(
        intro(None, None),
        pinai(),
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
    let described = async |registrations| {
        DescribeInstance::new(
            intro(None, None),
            pinai(),
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
