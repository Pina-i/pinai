use std::sync::Arc;

use domain::e2ee::testing::{
    InMemoryDelivery, RecordingMlsFederation, RecordingMlsNotifier, SentMls,
};
use domain::e2ee::{
    CATCH_UP_LIMIT, Commit, CommitBlob, CommitLog, DeliveryError, Epoch, OutgoingWelcome,
    WelcomeBlob,
};
use domain::identity::testing::{InMemoryAccounts, InMemoryRemoteActors, account, remote_actor};
use domain::identity::{Account, ActorUri, InstanceOrigin, RemoteActor};
use domain::messaging::testing::{GroupNotice, InMemoryMessaging, RecordingGroupNotifier};
use domain::messaging::{Conversations, GroupName, GroupSnapshot, Member, Role};
use domain::social::testing::{BLOCKED, KEPT_OUT_BY_THE_SETTING, StubReachability};
use domain::{ConversationId, DeviceId, UserId};
use time::{Duration, OffsetDateTime};

use super::*;

struct World {
    alice: Account,
    bob: Account,
    dave: Account,
    carol: RemoteActor,
    eve: RemoteActor,
    group: ConversationId,
    dm: ConversationId,
    store: Arc<InMemoryMessaging>,
    delivery: Arc<InMemoryDelivery>,
    notifier: Arc<RecordingMlsNotifier>,
    federation: Arc<RecordingMlsFederation>,
    groups: Arc<RecordingGroupNotifier>,
    reach: Arc<StubReachability>,
    append: AppendCommit,
    catch_up: CatchUpCommits,
    claim: ClaimWelcomes,
    send: SendWelcome,
    receive_commit: ReceiveCommit,
    receive_welcome: ReceiveWelcome,
    sweep: SweepWelcomes,
}

fn member(actor: &ActorUri, role: Role) -> Member {
    Member {
        actor_uri: actor.clone(),
        role,
    }
}

fn epoch(n: i64) -> Epoch {
    Epoch::parse(n).unwrap()
}

fn commit_blob(byte: u8) -> CommitBlob {
    CommitBlob::parse(vec![byte; 8]).unwrap()
}

fn welcome_blob(byte: u8) -> WelcomeBlob {
    WelcomeBlob::parse(vec![byte; 8]).unwrap()
}

async fn world() -> World {
    let (alice, bob, dave) = (account("alice"), account("bob"), account("dave"));
    let (carol, eve) = (
        remote_actor("carol_k2m9x@idp.carol.test"),
        remote_actor("eve_k2m9x@idp.eve.test"),
    );
    let accounts = Arc::new(InMemoryAccounts::with([
        alice.clone(),
        bob.clone(),
        dave.clone(),
    ]));
    let remote_actors = Arc::new(InMemoryRemoteActors::with([carol.clone(), eve.clone()]));
    let store = Arc::new(InMemoryMessaging::default());
    let group = store
        .create_group(
            Some(&GroupName::parse("crew").unwrap()),
            &[
                member(&alice.actor_uri, Role::Admin),
                member(&bob.actor_uri, Role::Member),
                member(&carol.actor_uri, Role::Member),
            ],
        )
        .await
        .unwrap()
        .id;
    let dm = store
        .open_dm(&alice.actor_uri, &bob.actor_uri, None)
        .await
        .unwrap();
    let delivery = Arc::new(InMemoryDelivery::default());
    let notifier = Arc::new(RecordingMlsNotifier::default());
    let federation = Arc::new(RecordingMlsFederation::default());
    let groups = Arc::new(RecordingGroupNotifier::default());
    let reach = Arc::new(StubReachability::default());
    World {
        append: AppendCommit::new(
            accounts.clone(),
            remote_actors.clone(),
            store.clone(),
            delivery.clone(),
            notifier.clone(),
            federation.clone(),
        ),
        catch_up: CatchUpCommits::new(accounts.clone(), store.clone(), delivery.clone()),
        claim: ClaimWelcomes::new(delivery.clone()),
        send: SendWelcome::new(
            InstanceOrigin::parse("http://localhost:8080").unwrap(),
            accounts.clone(),
            remote_actors,
            store.clone(),
            delivery.clone(),
            reach.clone(),
            notifier.clone(),
            federation.clone(),
        ),
        receive_commit: ReceiveCommit::new(
            accounts.clone(),
            store.clone(),
            delivery.clone(),
            notifier.clone(),
        ),
        receive_welcome: ReceiveWelcome::new(
            accounts,
            store.clone(),
            delivery.clone(),
            reach.clone(),
            notifier.clone(),
            groups.clone(),
        ),
        sweep: SweepWelcomes::new(delivery.clone()),
        alice,
        bob,
        dave,
        carol,
        eve,
        group,
        dm,
        store,
        delivery,
        notifier,
        federation,
        groups,
        reach,
    }
}

impl World {
    async fn commit(&self, by: &Account, at: i64) -> Result<Commit, DeliveryError> {
        self.append
            .execute(by.id, self.group, epoch(at), commit_blob(at as u8))
            .await
    }

    async fn stored(&self, conversation: ConversationId) -> Vec<Commit> {
        self.delivery
            .since(conversation, epoch(0), 1000)
            .await
            .unwrap()
    }

    async fn welcome(
        &self,
        from: &Account,
        to: &ActorUri,
        conversation: ConversationId,
    ) -> Result<Option<domain::e2ee::Welcome>, DeliveryError> {
        self.send
            .execute(
                from.id,
                to,
                DeviceId::generate(),
                conversation,
                welcome_blob(1),
            )
            .await
    }

    fn incoming_welcome(
        &self,
        from: &ActorUri,
        conversation: ConversationId,
        roster: Option<GroupSnapshot>,
    ) -> IncomingWelcome {
        IncomingWelcome {
            recipient: self.alice.id,
            sender: from.clone(),
            conversation,
            device: DeviceId::generate(),
            blob: welcome_blob(5),
            roster,
        }
    }
}

#[tokio::test]
async fn a_members_commit_is_stored_and_reaches_every_member() {
    let w = world().await;

    let commit = w.commit(&w.alice, 1).await.unwrap();

    assert_eq!(
        (commit.conversation, commit.epoch, &commit.proposer),
        (w.group, epoch(1), &w.alice.actor_uri)
    );
    assert_eq!(w.stored(w.group).await, vec![commit.clone()]);
    let mut told: Vec<UserId> = w.notifier.committed().iter().map(|(to, _)| *to).collect();
    told.sort();
    let mut members = vec![w.alice.id, w.bob.id];
    members.sort();
    assert_eq!(told, members, "the proposer's own sessions too");
    assert_eq!(
        w.federation.sent(),
        vec![SentMls::Commit {
            from: w.alice.actor_uri.clone(),
            to: w.carol.actor_uri.clone(),
            commit,
        }]
    );
}

#[tokio::test]
async fn a_commit_at_a_taken_epoch_answers_the_one_there() {
    let w = world().await;
    let first = w.commit(&w.alice, 2).await.unwrap();

    let lost = w.commit(&w.bob, 2).await;

    assert!(
        matches!(&lost, Err(DeliveryError::EpochTaken(winner)) if **winner == first),
        "{lost:?}"
    );
    assert_eq!(w.stored(w.group).await, vec![first]);
}

#[tokio::test]
async fn a_non_member_commits_nothing() {
    let w = world().await;

    let refused = w.commit(&w.dave, 1).await;

    assert!(
        matches!(refused, Err(DeliveryError::NotAMember)),
        "{refused:?}"
    );
    assert!(w.stored(w.group).await.is_empty());
    assert!(w.notifier.committed().is_empty());
}

#[tokio::test]
async fn a_commit_into_an_unknown_conversation_is_refused_at_any_epoch() {
    let w = world().await;
    let unknown = ConversationId::generate();

    for at in [0, 1, 2] {
        let refused = w
            .append
            .execute(w.alice.id, unknown, epoch(at), commit_blob(1))
            .await;

        assert!(
            matches!(refused, Err(DeliveryError::ConversationNotFound)),
            "epoch {at}: {refused:?}"
        );
    }
    assert_eq!(Conversations::find(&*w.store, unknown).await.unwrap(), None);
    assert!(w.stored(unknown).await.is_empty());
}

#[tokio::test]
async fn a_member_catches_up_after_an_epoch_a_page_at_a_time() {
    let w = world().await;
    for at in 1..=3 {
        w.commit(&w.alice, at).await.unwrap();
    }

    let page = w
        .catch_up
        .execute(w.bob.id, w.group, epoch(1))
        .await
        .unwrap();

    assert_eq!(
        page.commits.iter().map(|c| c.epoch).collect::<Vec<_>>(),
        vec![epoch(2), epoch(3)]
    );
    assert!(!page.has_more);
    for at in 4..=(CATCH_UP_LIMIT as i64 + 1) {
        w.commit(&w.alice, at).await.unwrap();
    }
    let full = w
        .catch_up
        .execute(w.bob.id, w.group, epoch(0))
        .await
        .unwrap();
    assert_eq!((full.commits.len(), full.has_more), (CATCH_UP_LIMIT, true));
}

#[tokio::test]
async fn only_a_member_catches_up_on_a_conversation_that_exists() {
    let w = world().await;

    let outsider = w.catch_up.execute(w.dave.id, w.group, epoch(0)).await;
    let unknown = w
        .catch_up
        .execute(w.alice.id, ConversationId::generate(), epoch(0))
        .await;

    assert!(
        matches!(outsider, Err(DeliveryError::NotAMember)),
        "{outsider:?}"
    );
    assert!(
        matches!(unknown, Err(DeliveryError::ConversationNotFound)),
        "{unknown:?}"
    );
}

#[tokio::test]
async fn a_welcome_for_a_local_member_waits_for_its_device_and_is_claimed_once() {
    let w = world().await;
    let (laptop, phone) = (DeviceId::generate(), DeviceId::generate());

    let welcome = w
        .send
        .execute(
            w.alice.id,
            &w.bob.actor_uri,
            laptop,
            w.group,
            welcome_blob(1),
        )
        .await
        .unwrap()
        .expect("stored here");

    assert_eq!(
        (welcome.recipient, welcome.device, welcome.conversation),
        (w.bob.id, laptop, w.group)
    );
    assert_eq!(
        w.notifier.welcomes_ready(),
        vec![(w.bob.id, welcome.clone())]
    );
    assert!(w.claim.execute(w.bob.id, phone).await.unwrap().is_empty());
    assert_eq!(
        w.claim.execute(w.bob.id, laptop).await.unwrap(),
        vec![welcome]
    );
    assert!(w.claim.execute(w.bob.id, laptop).await.unwrap().is_empty());
    assert!(w.federation.sent().is_empty());
}

#[tokio::test]
async fn a_welcome_for_a_remote_member_travels_with_the_groups_roster() {
    let w = world().await;
    let device = DeviceId::generate();

    let sent = w
        .send
        .execute(
            w.alice.id,
            &w.carol.actor_uri,
            device,
            w.group,
            welcome_blob(2),
        )
        .await
        .unwrap();

    assert_eq!(sent, None);
    let roster = GroupSnapshot {
        name: Some("crew".to_owned()),
        members: w.store.members(w.group).await.unwrap(),
    };
    assert_eq!(
        w.federation.sent(),
        vec![SentMls::Welcome {
            from: w.alice.actor_uri.clone(),
            to: w.carol.actor_uri.clone(),
            welcome: OutgoingWelcome {
                device,
                conversation: w.group,
                blob: welcome_blob(2),
                roster: Some(roster),
            },
        }]
    );
}

#[tokio::test]
async fn a_dms_welcome_travels_without_a_roster() {
    let w = world().await;
    let dm = w
        .store
        .open_dm(&w.alice.actor_uri, &w.carol.actor_uri, None)
        .await
        .unwrap();

    w.send
        .execute(
            w.alice.id,
            &w.carol.actor_uri,
            DeviceId::generate(),
            dm,
            welcome_blob(3),
        )
        .await
        .unwrap();

    assert!(matches!(
        &w.federation.sent()[..],
        [SentMls::Welcome { welcome, .. }] if welcome.roster.is_none()
    ));
}

#[tokio::test]
async fn a_welcome_for_an_unknown_local_account_is_refused() {
    let w = world().await;
    let nobody = ActorUri::parse("http://localhost:8080/users/nobody_t3st0").unwrap();

    let refused = w
        .send
        .execute(
            w.alice.id,
            &nobody,
            DeviceId::generate(),
            w.group,
            welcome_blob(1),
        )
        .await;

    assert!(
        matches!(refused, Err(DeliveryError::RecipientNotFound)),
        "{refused:?}"
    );
}

#[tokio::test]
async fn a_welcome_goes_from_a_member_to_a_member_and_makes_nobody_one() {
    let w = world().await;
    let outsider_in = w.welcome(&w.bob, &w.dave.actor_uri, w.dm).await;
    let from_outside = w.welcome(&w.dave, &w.bob.actor_uri, w.group).await;
    let remote_outsider = w.welcome(&w.alice, &w.eve.actor_uri, w.group).await;
    let unknown = w
        .welcome(&w.alice, &w.bob.actor_uri, ConversationId::generate())
        .await;

    assert!(
        matches!(outsider_in, Err(DeliveryError::RecipientNotAMember)),
        "{outsider_in:?}"
    );
    assert!(
        matches!(from_outside, Err(DeliveryError::NotAMember)),
        "{from_outside:?}"
    );
    assert!(
        matches!(remote_outsider, Err(DeliveryError::RecipientNotAMember)),
        "{remote_outsider:?}"
    );
    assert!(
        matches!(unknown, Err(DeliveryError::ConversationNotFound)),
        "{unknown:?}"
    );
    assert_eq!(w.store.members(w.dm).await.unwrap().len(), 2);
    assert!(w.notifier.welcomes_ready().is_empty());
    assert!(w.federation.sent().is_empty());
}

#[tokio::test]
async fn a_member_who_left_hands_out_no_welcome() {
    let w = world().await;
    w.store
        .remove_member(w.group, &w.bob.actor_uri)
        .await
        .unwrap();

    let rejoin = w
        .send
        .execute(
            w.bob.id,
            &w.bob.actor_uri,
            DeviceId::generate(),
            w.group,
            welcome_blob(1),
        )
        .await;

    assert!(
        matches!(rejoin, Err(DeliveryError::NotAMember)),
        "{rejoin:?}"
    );
    assert!(
        !w.store
            .members(w.group)
            .await
            .unwrap()
            .iter()
            .any(|m| m.actor_uri == w.bob.actor_uri)
    );
}

#[tokio::test]
async fn an_inbound_commit_from_outside_the_conversation_is_refused() {
    let w = world().await;
    let from = |proposer: &ActorUri, conversation| IncomingCommit {
        proposer: proposer.clone(),
        conversation,
        epoch: epoch(9),
        blob: commit_blob(9),
    };

    let outsider = w
        .receive_commit
        .execute(from(&w.eve.actor_uri, w.group))
        .await;
    let unknown = w
        .receive_commit
        .execute(from(&w.carol.actor_uri, ConversationId::generate()))
        .await;

    assert!(
        matches!(outsider, Err(DeliveryError::NotAMember)),
        "{outsider:?}"
    );
    assert!(
        matches!(unknown, Err(DeliveryError::ConversationNotFound)),
        "{unknown:?}"
    );
    assert!(w.stored(w.group).await.is_empty());
    assert!(w.notifier.committed().is_empty());
}

#[tokio::test]
async fn an_inbound_welcome_into_a_dm_it_is_not_in_is_refused() {
    let w = world().await;

    let refused = w
        .receive_welcome
        .execute(w.incoming_welcome(&w.eve.actor_uri, w.dm, None))
        .await;

    assert!(
        matches!(refused, Err(DeliveryError::NotAMember)),
        "{refused:?}"
    );
    assert!(w.notifier.welcomes_ready().is_empty());
    assert_eq!(w.store.members(w.dm).await.unwrap().len(), 2);
}

#[tokio::test]
async fn an_inbound_dm_welcome_that_outruns_its_dm_opens_it() {
    let w = world().await;
    let dm = ConversationId::generate();

    w.receive_welcome
        .execute(w.incoming_welcome(&w.carol.actor_uri, dm, None))
        .await
        .unwrap();

    let mut members: Vec<ActorUri> = w
        .store
        .members(dm)
        .await
        .unwrap()
        .into_iter()
        .map(|m| m.actor_uri)
        .collect();
    members.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    let mut pair = vec![w.alice.actor_uri.clone(), w.carol.actor_uri.clone()];
    pair.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    assert_eq!(members, pair);
    assert_eq!(w.notifier.welcomes_ready().len(), 1);
}

#[tokio::test]
async fn an_inbound_commit_is_stored_once_and_reaches_the_local_members() {
    let w = world().await;
    let incoming = || IncomingCommit {
        proposer: w.carol.actor_uri.clone(),
        conversation: w.group,
        epoch: epoch(5),
        blob: commit_blob(5),
    };

    w.receive_commit.execute(incoming()).await.unwrap();
    w.receive_commit.execute(incoming()).await.unwrap();

    let stored = w.stored(w.group).await;
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].proposer, w.carol.actor_uri);
    let mut told: Vec<UserId> = w.notifier.committed().iter().map(|(to, _)| *to).collect();
    told.sort();
    let mut members = vec![w.alice.id, w.bob.id];
    members.sort();
    assert_eq!(told, members, "once each");
}

#[tokio::test]
async fn an_inbound_welcome_mirrors_the_group_and_announces_it_to_the_newcomer_once() {
    let w = world().await;
    let group = ConversationId::generate();
    let roster = GroupSnapshot {
        name: Some("crew".to_owned()),
        members: vec![
            member(&w.carol.actor_uri, Role::Admin),
            member(&w.alice.actor_uri, Role::Member),
        ],
    };

    for _ in 0..2 {
        w.receive_welcome
            .execute(w.incoming_welcome(&w.carol.actor_uri, group, Some(roster.clone())))
            .await
            .unwrap();
    }

    assert_eq!(w.store.members(group).await.unwrap().len(), 2);
    assert_eq!(
        w.groups.sent(),
        vec![GroupNotice::Joined(
            w.alice.id,
            group,
            w.carol.actor_uri.clone()
        )]
    );
    let ready: Vec<(UserId, ConversationId)> = w
        .notifier
        .welcomes_ready()
        .iter()
        .map(|(to, welcome)| (*to, welcome.conversation))
        .collect();
    assert_eq!(ready, vec![(w.alice.id, group), (w.alice.id, group)]);
}

#[tokio::test]
async fn an_inbound_welcome_with_an_empty_roster_mirrors_nothing_and_admits_nobody() {
    let w = world().await;
    let group = ConversationId::generate();

    let refused = w
        .receive_welcome
        .execute(w.incoming_welcome(
            &w.carol.actor_uri,
            group,
            Some(GroupSnapshot {
                name: Some("crew".to_owned()),
                members: Vec::new(),
            }),
        ))
        .await;

    assert!(refused.is_err(), "{refused:?}");
    assert_eq!(Conversations::find(&*w.store, group).await.unwrap(), None);
    assert!(w.groups.sent().is_empty());
    assert!(w.notifier.welcomes_ready().is_empty());
}

#[tokio::test]
async fn an_inbound_welcome_whose_roster_its_sender_may_not_assert_is_refused() {
    let w = world().await;
    let roster = GroupSnapshot {
        name: Some("crew".to_owned()),
        members: vec![member(&w.alice.actor_uri, Role::Member)],
    };
    let group = ConversationId::generate();

    let refused = w
        .receive_welcome
        .execute(w.incoming_welcome(&w.eve.actor_uri, group, Some(roster)))
        .await;

    assert!(
        matches!(refused, Err(DeliveryError::NotAMember)),
        "{refused:?}"
    );
    assert_eq!(Conversations::find(&*w.store, group).await.unwrap(), None);
    assert!(w.notifier.welcomes_ready().is_empty());
}

#[tokio::test]
async fn claimed_welcomes_are_swept_once_their_grace_is_over() {
    let w = world().await;
    let device = DeviceId::generate();
    w.send
        .execute(
            w.alice.id,
            &w.bob.actor_uri,
            device,
            w.group,
            welcome_blob(1),
        )
        .await
        .unwrap();
    w.claim.execute(w.bob.id, device).await.unwrap();
    let now = OffsetDateTime::now_utc();

    let within = w.sweep.execute(now).await.unwrap();
    let after = w.sweep.execute(now + Duration::days(2)).await.unwrap();

    assert_eq!((within, after), (0, 1));
}

fn crew_with_alice(w: &World) -> GroupSnapshot {
    GroupSnapshot {
        name: Some("crew".to_owned()),
        members: vec![
            member(&w.carol.actor_uri, Role::Admin),
            member(&w.alice.actor_uri, Role::Member),
        ],
    }
}

#[tokio::test]
async fn a_dms_welcome_to_a_local_member_who_does_not_admit_the_sender_is_refused() {
    let mut refusals = Vec::new();
    for kept_out in [BLOCKED, KEPT_OUT_BY_THE_SETTING] {
        let w = world().await;
        w.reach.set(w.bob.id, &w.alice.actor_uri, kept_out);

        let refused = w.welcome(&w.alice, &w.bob.actor_uri, w.dm).await;

        refusals.push(format!("{:?}", refused.map(|_| ())));
        assert!(w.notifier.welcomes_ready().is_empty());
    }
    assert_eq!(refusals, vec!["Err(Unreachable)"; 2]);
}

/// Joining a group went through its own checks; a Welcome there only admits a member's device.
#[tokio::test]
async fn a_groups_welcome_and_ones_own_are_never_checked() {
    let w = world().await;
    w.reach.set(w.bob.id, &w.alice.actor_uri, BLOCKED);
    w.reach
        .set(w.alice.id, &w.alice.actor_uri, KEPT_OUT_BY_THE_SETTING);

    let to_bob = w.welcome(&w.alice, &w.bob.actor_uri, w.group).await;
    let to_herself = w.welcome(&w.alice, &w.alice.actor_uri, w.dm).await;

    assert!(to_bob.is_ok(), "{:?}", to_bob.map(|_| ()));
    assert!(to_herself.is_ok(), "{:?}", to_herself.map(|_| ()));
}

#[tokio::test]
async fn an_inbound_dm_welcome_from_someone_who_cannot_reach_the_recipient_opens_nothing() {
    let mut refusals = Vec::new();
    for kept_out in [BLOCKED, KEPT_OUT_BY_THE_SETTING] {
        let w = world().await;
        w.reach.set(w.alice.id, &w.carol.actor_uri, kept_out);
        let dm = ConversationId::generate();

        let refused = w
            .receive_welcome
            .execute(w.incoming_welcome(&w.carol.actor_uri, dm, None))
            .await;

        refusals.push(format!("{refused:?}"));
        assert_eq!(Conversations::find(&*w.store, dm).await.unwrap(), None);
        assert!(w.notifier.welcomes_ready().is_empty());
    }
    assert_eq!(refusals, vec!["Err(Unreachable)"; 2]);
}

#[tokio::test]
async fn an_inbound_welcome_into_a_group_new_here_from_someone_kept_out_mirrors_nothing() {
    let w = world().await;
    w.reach
        .set(w.alice.id, &w.carol.actor_uri, KEPT_OUT_BY_THE_SETTING);
    let group = ConversationId::generate();

    let refused = w
        .receive_welcome
        .execute(w.incoming_welcome(&w.carol.actor_uri, group, Some(crew_with_alice(&w))))
        .await;

    assert!(
        matches!(refused, Err(DeliveryError::Unreachable)),
        "{refused:?}"
    );
    assert_eq!(Conversations::find(&*w.store, group).await.unwrap(), None);
    assert!(w.groups.sent().is_empty());
    assert!(w.notifier.welcomes_ready().is_empty());
}

#[tokio::test]
async fn an_inbound_welcome_into_a_group_the_recipient_is_in_is_never_checked() {
    let w = world().await;
    w.reach.set(w.alice.id, &w.carol.actor_uri, BLOCKED);
    let roster = GroupSnapshot {
        name: Some("crew".to_owned()),
        members: vec![
            member(&w.alice.actor_uri, Role::Admin),
            member(&w.bob.actor_uri, Role::Member),
            member(&w.carol.actor_uri, Role::Member),
        ],
    };

    let welcomed = w
        .receive_welcome
        .execute(w.incoming_welcome(&w.carol.actor_uri, w.group, Some(roster)))
        .await;

    assert!(welcomed.is_ok(), "{welcomed:?}");
}

#[tokio::test]
async fn an_inbound_welcome_into_a_dm_the_two_already_share_is_checked_too() {
    let w = world().await;
    let dm = w
        .store
        .open_dm(&w.alice.actor_uri, &w.carol.actor_uri, None)
        .await
        .unwrap();
    w.reach.set(w.alice.id, &w.carol.actor_uri, BLOCKED);

    let refused = w
        .receive_welcome
        .execute(w.incoming_welcome(&w.carol.actor_uri, dm, None))
        .await;

    assert!(
        matches!(refused, Err(DeliveryError::Unreachable)),
        "{refused:?}"
    );
    assert!(w.notifier.welcomes_ready().is_empty());
}
