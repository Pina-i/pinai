//! The people search's in-memory fake, the seeds it reads, and the contract every search must
//! satisfy.

use std::sync::Mutex;

use time::OffsetDateTime;
use unicode_normalization::UnicodeNormalization;
use unicode_normalization::char::is_combining_mark;

use crate::identity::{Account, ActorUri, Handle, RemoteActor};
use crate::messaging::ConversationKind;
use crate::social::{
    Direction, FoundPerson, Friendship, FriendshipStatus, GroupPerson, PeopleFound, PeopleSearch,
    SearchQuery, SocialStoreError, Ties,
};
use crate::{ConversationId, FriendshipId, UserId};

/// How a local account got in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    Confirmed,
    /// Let in by an admin, its address never confirmed.
    Admitted,
    /// A sign-up still to confirm its address.
    Unconfirmed,
}

/// Seeds what a search reads, which other contexts write.
#[async_trait::async_trait]
pub trait PeopleSeeds: Send + Sync {
    async fn sign_up(&self, account: &Account, admission: Admission);
    /// A remote actor this instance caches.
    async fn remember(&self, actor: &RemoteActor);
    /// `owner`'s side of a friendship or a request with `friend`.
    async fn befriend(
        &self,
        owner: UserId,
        friend: &ActorUri,
        status: FriendshipStatus,
        direction: Direction,
    ) -> FriendshipId;
    async fn block(&self, owner: UserId, actor: &ActorUri);
    /// A conversation the members are all in.
    async fn converse(
        &self,
        kind: ConversationKind,
        name: Option<&str>,
        created_at: OffsetDateTime,
        members: &[&ActorUri],
    ) -> ConversationId;
    async fn leave(&self, conversation: ConversationId, member: &ActorUri);
}

struct Conversation {
    id: ConversationId,
    kind: ConversationKind,
    name: Option<String>,
    created_at: OffsetDateTime,
    /// Each member, and whether they are still in it.
    members: Vec<(ActorUri, bool)>,
}

impl Conversation {
    fn holds(&self, actor: &ActorUri) -> bool {
        self.members.iter().any(|(a, active)| a == actor && *active)
    }
}

#[derive(Default)]
struct World {
    accounts: Vec<(Account, Admission)>,
    remote: Vec<RemoteActor>,
    sides: Vec<Friendship>,
    blocks: Vec<(UserId, ActorUri)>,
    conversations: Vec<Conversation>,
}

impl World {
    fn ties(&self, owner: UserId, actor: &ActorUri) -> Ties {
        Ties {
            blocked: self.blocks.iter().any(|(o, a)| *o == owner && a == actor),
            side: self
                .sides
                .iter()
                .find(|s| s.owner == owner && &s.friend == actor)
                .cloned(),
        }
    }

    fn found(
        &self,
        caller: UserId,
        actor: &ActorUri,
        name: &Option<String>,
        avatar: &Option<String>,
    ) -> Option<FoundPerson> {
        Some(FoundPerson {
            address: actor.federated_address()?,
            actor: actor.clone(),
            display_name: name.clone(),
            avatar_url: avatar.clone(),
            ties: self.ties(caller, actor),
        })
    }
}

/// Searches what it was seeded with, folding names as Postgres's `unaccent` does Latin letters.
#[derive(Default)]
pub struct InMemoryPeopleSearch {
    world: Mutex<World>,
}

/// NFKD without its combining marks, in lower case.
fn fold(text: &str) -> String {
    text.nfkd()
        .filter(|c| !is_combining_mark(*c))
        .collect::<String>()
        .to_lowercase()
}

/// 0 when the folded name starts with the query, 1 when it holds it.
fn tier_by_name(folded: Option<&str>, query: &str) -> Option<u8> {
    let name = folded?;
    if name.starts_with(query) {
        Some(0)
    } else {
        name.contains(query).then_some(1)
    }
}

struct Rank {
    tier: u8,
    folded: Option<String>,
}

/// By tier, then folded name — none last —, then actor URI, as bytes; at most `limit`.
fn ranked<T>(found: &mut Vec<(Rank, T)>, actor: impl Fn(&T) -> &ActorUri, limit: usize) {
    found.sort_by(|(a, x), (b, y)| {
        (a.tier, a.folded.is_none(), &a.folded, actor(x).as_str()).cmp(&(
            b.tier,
            b.folded.is_none(),
            &b.folded,
            actor(y).as_str(),
        ))
    });
    found.truncate(limit);
}

#[async_trait::async_trait]
impl PeopleSearch for InMemoryPeopleSearch {
    async fn search(
        &self,
        caller: UserId,
        query: &SearchQuery,
        limit: i64,
    ) -> Result<PeopleFound, SocialStoreError> {
        let world = self.world.lock().unwrap();
        let query = fold(query.as_str());
        let limit = usize::try_from(limit).unwrap_or(0);
        let me = world
            .accounts
            .iter()
            .find(|(a, _)| a.id == caller)
            .map(|(a, _)| &a.actor_uri);

        let mut server: Vec<(Rank, FoundPerson)> = world
            .accounts
            .iter()
            .filter(|(a, admission)| a.id != caller && *admission != Admission::Unconfirmed)
            .filter_map(|(a, _)| {
                let folded = a.display_name.as_deref().map(fold);
                let tier = tier_by_name(folded.as_deref(), &query)
                    .or_else(|| a.username.contains(&query).then_some(2))?;
                let person = world.found(caller, &a.actor_uri, &a.display_name, &a.avatar_url)?;
                Some((Rank { tier, folded }, person))
            })
            .collect();
        ranked(&mut server, |p| &p.actor, limit);

        let mut groups: Vec<(Rank, GroupPerson)> = world
            .remote
            .iter()
            .filter(|r| {
                !world
                    .accounts
                    .iter()
                    .any(|(a, _)| a.actor_uri == r.actor_uri)
            })
            .filter_map(|r| {
                let me = me?;
                let latest = world
                    .conversations
                    .iter()
                    .filter(|c| {
                        c.kind == ConversationKind::Group && c.holds(me) && c.holds(&r.actor_uri)
                    })
                    .max_by_key(|c| (c.created_at, c.id))?;
                let folded = r.display_name.as_deref().map(fold);
                let tier = tier_by_name(folded.as_deref(), &query)?;
                let person = world.found(caller, &r.actor_uri, &r.display_name, &r.avatar_url)?;
                let group = latest.name.clone();
                Some((Rank { tier, folded }, GroupPerson { person, group }))
            })
            .collect();
        ranked(&mut groups, |g| &g.person.actor, limit);

        Ok(PeopleFound {
            server: server.into_iter().map(|(_, p)| p).collect(),
            groups: groups.into_iter().map(|(_, g)| g).collect(),
        })
    }

    async fn local(
        &self,
        caller: UserId,
        handle: &Handle,
    ) -> Result<Option<FoundPerson>, SocialStoreError> {
        let world = self.world.lock().unwrap();
        Ok(world
            .accounts
            .iter()
            .find(|(a, admission)| {
                a.username == handle.as_str() && *admission != Admission::Unconfirmed
            })
            .and_then(|(a, _)| world.found(caller, &a.actor_uri, &a.display_name, &a.avatar_url)))
    }

    async fn ties(&self, caller: UserId, actor: &ActorUri) -> Result<Ties, SocialStoreError> {
        Ok(self.world.lock().unwrap().ties(caller, actor))
    }
}

#[async_trait::async_trait]
impl PeopleSeeds for InMemoryPeopleSearch {
    async fn sign_up(&self, account: &Account, admission: Admission) {
        let mut world = self.world.lock().unwrap();
        world.accounts.push((account.clone(), admission));
    }

    async fn remember(&self, actor: &RemoteActor) {
        self.world.lock().unwrap().remote.push(actor.clone());
    }

    async fn befriend(
        &self,
        owner: UserId,
        friend: &ActorUri,
        status: FriendshipStatus,
        direction: Direction,
    ) -> FriendshipId {
        let id = FriendshipId::generate();
        self.world.lock().unwrap().sides.push(Friendship {
            id,
            owner,
            friend: friend.clone(),
            status,
            direction,
        });
        id
    }

    async fn block(&self, owner: UserId, actor: &ActorUri) {
        let mut world = self.world.lock().unwrap();
        world.blocks.push((owner, actor.clone()));
    }

    async fn converse(
        &self,
        kind: ConversationKind,
        name: Option<&str>,
        created_at: OffsetDateTime,
        members: &[&ActorUri],
    ) -> ConversationId {
        let id = ConversationId::generate();
        self.world.lock().unwrap().conversations.push(Conversation {
            id,
            kind,
            name: name.map(str::to_owned),
            created_at,
            members: members.iter().map(|m| ((*m).clone(), true)).collect(),
        });
        id
    }

    async fn leave(&self, conversation: ConversationId, member: &ActorUri) {
        let mut world = self.world.lock().unwrap();
        for c in world
            .conversations
            .iter_mut()
            .filter(|c| c.id == conversation)
        {
            for (_, active) in c.members.iter_mut().filter(|(a, _)| a == member) {
                *active = false;
            }
        }
    }
}

/// Run against the in-memory fake and the Postgres adapter, each over a store nobody seeded.
/// Names keep to Latin accents, which `unaccent` and the fake fold alike.
pub mod contract {
    use time::{Duration, OffsetDateTime};

    use super::{Admission, PeopleSeeds};
    use crate::identity::testing::remote_actor;
    use crate::identity::{Account, ActorUri, FederatedAddress, Handle, RemoteActor};
    use crate::messaging::ConversationKind;
    use crate::social::{
        Direction, FoundPerson, FriendshipStatus, GroupPerson, PeopleFound, PeopleSearch,
        SearchQuery, Standing, Ties,
    };
    use crate::{ConversationId, UserId};

    /// An account of `localhost:8080` named `name`, its handle `{handle}_t3st0`.
    fn local(name: &str, handle: &str) -> Account {
        let username = format!("{handle}_t3st0");
        Account {
            id: UserId::generate(),
            actor_uri: ActorUri::parse(&format!("http://localhost:8080/users/{username}")).unwrap(),
            username,
            display_name: Some(name.to_owned()),
            avatar_url: None,
        }
    }

    async fn signed_up(seeds: &dyn PeopleSeeds, name: &str, handle: &str) -> Account {
        let account = local(name, handle);
        seeds.sign_up(&account, Admission::Confirmed).await;
        account
    }

    /// An account of `idp.peer.test` named `name`, its handle `{handle}_k2m9x`.
    fn remote(name: &str, handle: &str) -> RemoteActor {
        RemoteActor {
            display_name: Some(name.to_owned()),
            ..remote_actor(&format!("{handle}_k2m9x@idp.peer.test"))
        }
    }

    /// The same, cached here.
    async fn remembered(seeds: &dyn PeopleSeeds, name: &str, handle: &str) -> RemoteActor {
        let actor = remote(name, handle);
        seeds.remember(&actor).await;
        actor
    }

    /// A group of `members`, created `minutes` into the test.
    async fn group(
        seeds: &dyn PeopleSeeds,
        name: Option<&str>,
        minutes: i64,
        members: &[&ActorUri],
    ) -> ConversationId {
        seeds
            .converse(ConversationKind::Group, name, at(minutes), members)
            .await
    }

    fn at(minutes: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap() + Duration::minutes(minutes)
    }

    async fn search(
        people: &dyn PeopleSearch,
        caller: &Account,
        query: &str,
        limit: i64,
    ) -> PeopleFound {
        people
            .search(caller.id, &SearchQuery::parse(query).unwrap(), limit)
            .await
            .unwrap()
    }

    fn names(found: &[FoundPerson]) -> Vec<&str> {
        found
            .iter()
            .map(|p| p.display_name.as_deref().unwrap_or_default())
            .collect()
    }

    fn group_names(found: &[GroupPerson]) -> Vec<&str> {
        found
            .iter()
            .map(|g| g.person.display_name.as_deref().unwrap_or_default())
            .collect()
    }

    pub async fn names_are_found_in_three_tiers_then_by_name(
        people: &dyn PeopleSearch,
        seeds: &dyn PeopleSeeds,
    ) {
        let alice = signed_up(seeds, "Alice", "alice").await;
        let locals = [
            ("Makana", "makana"),
            ("Pua", "puaka"),
            ("Kai", "kai"),
            ("Hina", "kahina"),
            ("Aka", "aka"),
            ("Kahu", "kahu"),
            ("Lani", "lani"),
            ("Kab", "kab"),
            ("Ka Lani", "kalani"),
        ];
        for (name, handle) in locals {
            signed_up(seeds, name, handle).await;
        }
        let kaleo = remembered(seeds, "Kaleo", "kaleo").await;
        let lokahi = remembered(seeds, "Lokahi", "lokahi").await;
        let pua = remembered(seeds, "Pua", "kapua").await;
        let me = &alice.actor_uri;
        let members = [me, &lokahi.actor_uri, &pua.actor_uri, &kaleo.actor_uri];
        group(seeds, Some("Lab"), 0, &members).await;

        let found = search(people, &alice, "ka", 20).await;

        assert_eq!(
            names(&found.server),
            [
                "Ka Lani", "Kab", "Kahu", "Kai", "Aka", "Makana", "Hina", "Pua"
            ],
            "a name starting with it, a name holding it, a handle holding it"
        );
        assert_eq!(
            group_names(&found.groups),
            ["Kaleo", "Lokahi"],
            "another instance's handle is never searched"
        );
    }

    pub async fn accents_and_case_never_matter_either_way(
        people: &dyn PeopleSearch,
        seeds: &dyn PeopleSeeds,
    ) {
        let alice = signed_up(seeds, "Alice", "alice").await;
        signed_up(seeds, "Hoku", "hokub").await;
        signed_up(seeds, "Hōkū", "hoku").await;
        let peer = remembered(seeds, "HŌKŪ", "hoku").await;
        group(seeds, None, 0, &[&alice.actor_uri, &peer.actor_uri]).await;

        for query in ["hoku", "Hōkū", "HOKŪ", "ōk"] {
            let found = search(people, &alice, query, 20).await;

            assert_eq!(
                names(&found.server),
                ["Hōkū", "Hoku"],
                "{query:?}: the same folded name, by actor URI"
            );
            assert_eq!(group_names(&found.groups), ["HŌKŪ"], "{query:?}");
        }
    }

    pub async fn a_query_is_taken_literally(people: &dyn PeopleSearch, seeds: &dyn PeopleSeeds) {
        let alice = signed_up(seeds, "Alice", "alice").await;
        signed_up(seeds, "100% Pono", "pono").await;
        signed_up(seeds, "Lei_Ana", "leiana").await;
        signed_up(seeds, "Kalei Ana", "kaleiana").await;

        let expected: [(&str, &[&str]); 4] = [
            ("0%", &["100% Pono"]),
            ("%p", &[]),
            ("i_a", &["Lei_Ana"]),
            ("a\\", &[]),
        ];
        for (query, names_found) in expected {
            let found = search(people, &alice, query, 20).await;

            assert_eq!(names(&found.server), names_found, "{query:?}");
        }
    }

    pub async fn the_caller_and_sign_ups_still_to_confirm_are_never_listed(
        people: &dyn PeopleSearch,
        seeds: &dyn PeopleSeeds,
    ) {
        let kai = signed_up(seeds, "Kai", "kai").await;
        let others = [
            ("Kailani", "kailani", Admission::Confirmed),
            ("Kaimana", "kaimana", Admission::Admitted),
            ("Kaiah", "kaiah", Admission::Unconfirmed),
        ];
        for (name, handle, admission) in others {
            seeds.sign_up(&local(name, handle), admission).await;
        }

        let found = search(people, &kai, "kai", 20).await;
        let unknown = search(people, &local("Kaipo", "kaipo"), "kai", 20).await;

        assert_eq!(names(&found.server), ["Kailani", "Kaimana"]);
        assert_eq!(
            names(&unknown.server),
            ["Kai", "Kailani", "Kaimana"],
            "a caller this instance doesn't hold is answered all the same"
        );
    }

    pub async fn groups_hold_the_remote_active_members_of_the_callers_groups_only(
        people: &dyn PeopleSearch,
        seeds: &dyn PeopleSeeds,
    ) {
        let alice = signed_up(seeds, "Alice", "alice").await;
        let keola = Account {
            avatar_url: Some("http://localhost:8080/avatars/keola.webp?v=2".to_owned()),
            ..local("Keola", "keola")
        };
        seeds.sign_up(&keola, Admission::Confirmed).await;
        // Cached as a remote actor too: only being an account here keeps her out of `groups`.
        seeds
            .remember(&RemoteActor {
                actor_uri: keola.actor_uri.clone(),
                inbox: url::Url::parse(&format!("{}/inbox", keola.actor_uri)).unwrap(),
                display_name: keola.display_name.clone(),
                avatar_url: None,
            })
            .await;
        let keoni = RemoteActor {
            avatar_url: Some("https://idp.peer.test/avatars/keoni.png".to_owned()),
            ..remote("Keoni", "keoni")
        };
        seeds.remember(&keoni).await;
        let mut others = Vec::new();
        for name in ["Kealoha", "Keahi", "Keawe", "Kekoa", "Kehau"] {
            others.push(remembered(seeds, name, &name.to_lowercase()).await);
        }
        let [kealoha, keahi, keawe, kekoa, kehau] = [0, 1, 2, 3, 4].map(|i| &others[i].actor_uri);
        let me = &alice.actor_uri;
        group(
            seeds,
            Some("Lab"),
            0,
            &[me, &keola.actor_uri, &keoni.actor_uri],
        )
        .await;
        let left = group(seeds, Some("Left"), 1, &[me, kealoha]).await;
        seeds.leave(left, me).await;
        let they_left = group(seeds, Some("Gone"), 2, &[me, keahi]).await;
        seeds.leave(they_left, keahi).await;
        seeds
            .converse(ConversationKind::Dm, None, at(3), &[me, keawe])
            .await;
        seeds
            .befriend(
                alice.id,
                kekoa,
                FriendshipStatus::Accepted,
                Direction::Outgoing,
            )
            .await;
        group(seeds, Some("Elsewhere"), 4, &[&keola.actor_uri, kehau]).await;

        let found = search(people, &alice, "ke", 20).await;

        assert_eq!(
            found.server,
            [FoundPerson {
                actor: keola.actor_uri.clone(),
                address: FederatedAddress::parse("keola_t3st0@localhost:8080").unwrap(),
                display_name: Some("Keola".to_owned()),
                avatar_url: keola.avatar_url.clone(),
                ties: Ties::default(),
            }],
            "a local co-member is in the server's section only"
        );
        assert_eq!(
            found.groups,
            [GroupPerson {
                person: FoundPerson {
                    actor: keoni.actor_uri.clone(),
                    address: FederatedAddress::parse("keoni_k2m9x@idp.peer.test").unwrap(),
                    display_name: Some("Keoni".to_owned()),
                    avatar_url: keoni.avatar_url.clone(),
                    ties: Ties::default(),
                },
                group: Some("Lab".to_owned()),
            }],
            "never a group left, by either, a 1:1, a friend met elsewhere, another's group"
        );
    }

    pub async fn a_group_person_comes_with_the_latest_group_shared(
        people: &dyn PeopleSearch,
        seeds: &dyn PeopleSeeds,
    ) {
        let alice = signed_up(seeds, "Alice", "alice").await;
        let mahina = remembered(seeds, "Mahina", "mahina").await;
        let malia = remembered(seeds, "Malia", "malia").await;
        let me = &alice.actor_uri;
        let (mahina, malia) = (&mahina.actor_uri, &malia.actor_uri);
        group(seeds, Some("Older"), 0, &[me, mahina]).await;
        group(seeds, Some("Newer"), 1, &[me, mahina]).await;
        let left = group(seeds, Some("Left since"), 2, &[me, mahina]).await;
        seeds.leave(left, me).await;
        seeds
            .converse(ConversationKind::Dm, None, at(3), &[me, mahina])
            .await;
        group(seeds, Some("Named"), 0, &[me, malia]).await;
        group(seeds, None, 1, &[me, malia]).await;

        let found = search(people, &alice, "ma", 20).await;

        let shared: Vec<_> = found
            .groups
            .iter()
            .map(|g| (g.person.display_name.as_deref(), g.group.as_deref()))
            .collect();
        assert_eq!(
            shared,
            [(Some("Mahina"), Some("Newer")), (Some("Malia"), None)]
        );
    }

    pub async fn each_person_comes_with_the_callers_standing(
        people: &dyn PeopleSearch,
        seeds: &dyn PeopleSeeds,
    ) {
        use Direction::{Incoming, Outgoing};
        use FriendshipStatus::{Accepted, Pending};

        let alice = signed_up(seeds, "Alice", "alice").await;
        let me = &alice.actor_uri;
        let blocked = signed_up(seeds, "Pua Blocked", "puablocked").await;
        let friend = signed_up(seeds, "Pua Friend", "puafriend").await;
        let asking = signed_up(seeds, "Pua Asking", "puaasking").await;
        let asked = signed_up(seeds, "Pua Asked", "puaasked").await;
        signed_up(seeds, "Pua Stranger", "puastranger").await;
        let blocking = signed_up(seeds, "Pua Blocking", "puablocking").await;
        seeds.block(alice.id, &blocked.actor_uri).await;
        seeds.block(blocking.id, me).await;
        seeds
            .befriend(alice.id, &friend.actor_uri, Accepted, Outgoing)
            .await;
        seeds.befriend(friend.id, me, Accepted, Incoming).await;
        let request = seeds
            .befriend(alice.id, &asking.actor_uri, Pending, Incoming)
            .await;
        seeds.befriend(asking.id, me, Pending, Outgoing).await;
        seeds
            .befriend(alice.id, &asked.actor_uri, Pending, Outgoing)
            .await;
        seeds.befriend(asked.id, me, Pending, Incoming).await;
        let remote = remembered(seeds, "Pua Remote", "puaremote").await;
        let far_friend = remembered(seeds, "Pua Elsewhere", "puaelsewhere").await;
        let remote_request = seeds
            .befriend(alice.id, &remote.actor_uri, Pending, Incoming)
            .await;
        seeds
            .befriend(alice.id, &far_friend.actor_uri, Accepted, Incoming)
            .await;
        group(
            seeds,
            Some("Lab"),
            0,
            &[me, &remote.actor_uri, &far_friend.actor_uri],
        )
        .await;

        let found = search(people, &alice, "pua", 20).await;

        let server: Vec<_> = found
            .server
            .iter()
            .map(|p| (p.display_name.as_deref(), p.ties.standing()))
            .collect();
        assert_eq!(
            server,
            [
                (Some("Pua Asked"), Standing::RequestSent),
                (Some("Pua Asking"), Standing::RequestReceived(request)),
                (Some("Pua Blocked"), Standing::Blocked),
                (Some("Pua Blocking"), Standing::Unrelated),
                (Some("Pua Friend"), Standing::Friend),
                (Some("Pua Stranger"), Standing::Unrelated),
            ],
            "a block the other made never shows"
        );
        let groups: Vec<_> = found
            .groups
            .iter()
            .map(|g| (g.person.display_name.as_deref(), g.person.ties.standing()))
            .collect();
        assert_eq!(
            groups,
            [
                (Some("Pua Elsewhere"), Standing::Friend),
                (
                    Some("Pua Remote"),
                    Standing::RequestReceived(remote_request)
                ),
            ]
        );
    }

    pub async fn each_section_holds_at_most_the_limit(
        people: &dyn PeopleSearch,
        seeds: &dyn PeopleSeeds,
    ) {
        let alice = signed_up(seeds, "Alice", "alice").await;
        let mut members = vec![alice.actor_uri.clone()];
        for i in 1..=3 {
            signed_up(seeds, &format!("Kai {i}"), &format!("kai{i}")).await;
            let peer = remembered(seeds, &format!("Kai R{i}"), &format!("kair{i}")).await;
            members.push(peer.actor_uri);
        }
        let members: Vec<&ActorUri> = members.iter().collect();
        group(seeds, None, 0, &members).await;

        let found = search(people, &alice, "kai", 2).await;

        assert_eq!(names(&found.server), ["Kai 1", "Kai 2"]);
        assert_eq!(group_names(&found.groups), ["Kai R1", "Kai R2"]);
    }

    pub async fn someone_without_an_address_is_left_out(
        people: &dyn PeopleSearch,
        seeds: &dyn PeopleSeeds,
    ) {
        let alice = signed_up(seeds, "Alice", "alice").await;
        let uri = ActorUri::parse("https://idp.peer.test/actors/7").unwrap();
        let addressless = RemoteActor {
            inbox: url::Url::parse("https://idp.peer.test/actors/7/inbox").unwrap(),
            actor_uri: uri,
            display_name: Some("Kai A".to_owned()),
            avatar_url: None,
        };
        seeds.remember(&addressless).await;
        let kai = remembered(seeds, "Kai B", "kaib").await;
        let members = [&alice.actor_uri, &addressless.actor_uri, &kai.actor_uri];
        group(seeds, None, 0, &members).await;

        let found = search(people, &alice, "kai", 1).await;

        assert_eq!(
            group_names(&found.groups),
            ["Kai B"],
            "left out before the limit is counted"
        );
    }

    pub async fn an_account_here_is_found_by_its_handle_with_the_callers_ties(
        people: &dyn PeopleSearch,
        seeds: &dyn PeopleSeeds,
    ) {
        use Direction::{Incoming, Outgoing};
        use FriendshipStatus::Pending;

        let alice = signed_up(seeds, "Alice", "alice").await;
        let hoku = Account {
            avatar_url: Some("http://localhost:8080/avatars/hoku.webp?v=2".to_owned()),
            ..local("Hōkū", "hoku")
        };
        seeds.sign_up(&hoku, Admission::Confirmed).await;
        let kai = local("Kai", "kai");
        seeds.sign_up(&kai, Admission::Admitted).await;
        let kaiah = local("Kaiah", "kaiah");
        seeds.sign_up(&kaiah, Admission::Unconfirmed).await;
        let request = seeds
            .befriend(alice.id, &hoku.actor_uri, Pending, Incoming)
            .await;
        seeds
            .befriend(hoku.id, &alice.actor_uri, Pending, Outgoing)
            .await;
        seeds.block(kai.id, &alice.actor_uri).await;
        let look_up = async |handle: &str| {
            let handle = Handle::parse(handle).unwrap();
            people.local(alice.id, &handle).await.unwrap()
        };

        let found = look_up("hoku_t3st0").await.expect("a confirmed account");
        let admitted = look_up("kai_t3st0").await.expect("an admitted account");
        let own = look_up("alice_t3st0")
            .await
            .expect("the caller's own account");

        assert_eq!(found.actor, hoku.actor_uri);
        assert_eq!(found.address.to_string(), "hoku_t3st0@localhost:8080");
        assert_eq!(found.display_name.as_deref(), Some("Hōkū"));
        assert_eq!(found.avatar_url, hoku.avatar_url);
        assert_eq!(found.ties.standing(), Standing::RequestReceived(request));
        assert_eq!(
            admitted.ties.standing(),
            Standing::Unrelated,
            "a block the other made never shows"
        );
        assert_eq!(own.actor, alice.actor_uri);
        assert_eq!(own.ties, Ties::default());
        assert_eq!(look_up("kaiah_t3st0").await, None, "still to confirm");
        assert_eq!(look_up("nobody_t3st0").await, None);
    }

    pub async fn the_callers_ties_to_anyone_are_read_alone(
        people: &dyn PeopleSearch,
        seeds: &dyn PeopleSeeds,
    ) {
        use Direction::{Incoming, Outgoing};
        use FriendshipStatus::{Accepted, Pending};

        let alice = signed_up(seeds, "Alice", "alice").await;
        let bob = signed_up(seeds, "Bob", "bob").await;
        let [blocked, friend, asked, asking, stranger] = ["pua", "keoni", "malia", "mahina", "kai"]
            .map(|handle| remote(handle, handle).actor_uri);
        seeds.block(alice.id, &blocked).await;
        seeds.befriend(alice.id, &friend, Accepted, Outgoing).await;
        seeds.befriend(alice.id, &asked, Pending, Outgoing).await;
        let request = seeds.befriend(alice.id, &asking, Pending, Incoming).await;
        seeds.befriend(bob.id, &stranger, Accepted, Incoming).await;
        seeds.block(bob.id, &alice.actor_uri).await;

        let expected = [
            (&blocked, Standing::Blocked),
            (&friend, Standing::Friend),
            (&asked, Standing::RequestSent),
            (&asking, Standing::RequestReceived(request)),
            (&stranger, Standing::Unrelated),
            (&bob.actor_uri, Standing::Unrelated),
        ];
        for (actor, standing) in expected {
            let ties = people.ties(alice.id, actor).await.unwrap();

            assert_eq!(ties.standing(), standing, "{actor}");
        }
    }
}

#[cfg(test)]
mod tests;
