use domain::identity::testing::{account, remote_actor};
use domain::messaging::ConversationKind;
use domain::social::testing::people::{Admission, InMemoryPeopleSearch, PeopleSeeds};
use time::OffsetDateTime;

use super::*;

#[tokio::test]
async fn each_section_answers_at_most_fifty_and_at_least_one() {
    let people = Arc::new(InMemoryPeopleSearch::default());
    let alice = account("alice");
    people.sign_up(&alice, Admission::Confirmed).await;
    let mut members = vec![alice.actor_uri.clone()];
    for i in 0..60 {
        people
            .sign_up(&account(&format!("user{i:02}")), Admission::Confirmed)
            .await;
        let peer = remote_actor(&format!("user{i:02}_k2m9x@idp.peer.test"));
        people.remember(&peer).await;
        members.push(peer.actor_uri);
    }
    let members: Vec<_> = members.iter().collect();
    people
        .converse(
            ConversationKind::Group,
            None,
            OffsetDateTime::now_utc(),
            &members,
        )
        .await;
    let search = SearchPeople::new(people);
    let user = SearchQuery::parse("user").unwrap();

    for (asked, answered) in [(500, 50), (0, 1), (-3, 1), (20, 20)] {
        let found = search.execute(alice.id, &user, asked).await.unwrap();

        assert_eq!(found.server.len(), answered, "{asked}");
        assert_eq!(found.groups.len(), answered, "{asked}");
    }
}
