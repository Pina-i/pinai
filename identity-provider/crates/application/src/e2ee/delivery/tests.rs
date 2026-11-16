use std::sync::Arc;

use domain::auth::Sessions;
use domain::auth::testing::InMemorySessions;
use domain::e2ee::testing::{
    InMemoryArchive, InMemoryDelivery, InMemoryKeyDirectory, RecordingMlsFederation,
    RecordingMlsNotifier, SentMls, external_commit, join_proposal, member_commit,
};
use domain::e2ee::{
    ApprovalPublicKey, ApprovalRequired, Attestation, CATCH_UP_LIMIT, Commit, CommitBlob,
    CommitLog, DeliveryError, DeviceLabel, DeviceRequired, DeviceRootKey, Devices, Epoch,
    GroupInfo, GroupInfoBlob, GroupInfos, HistoryCheckValue, HistoryGeneration, HistoryKey,
    HistoryKeys, HistorySalt, HpkeKeyWrite, OutgoingWelcome, WelcomeBlob,
};
use domain::identity::testing::{InMemoryAccounts, InMemoryRemoteActors, account, remote_actor};
use domain::identity::{Account, ActorUri, Bearer, InstanceOrigin, RemoteActor};
use domain::messaging::testing::{
    GroupNotice, InMemoryMessaging, RecordingGroupNotifier, unstamped,
};
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
    sessions: Arc<InMemorySessions>,
    archive: Arc<InMemoryArchive>,
    devices: Arc<InMemoryKeyDirectory>,
    notifier: Arc<RecordingMlsNotifier>,
    federation: Arc<RecordingMlsFederation>,
    groups: Arc<RecordingGroupNotifier>,
    reach: Arc<StubReachability>,
    append: AppendCommit,
    catch_up: CatchUpCommits,
    load_group_info: LoadGroupInfo,
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
    member_commit(byte)
}

fn welcome_blob(byte: u8) -> WelcomeBlob {
    WelcomeBlob::parse(vec![byte; 8]).unwrap()
}

fn group_info(byte: u8) -> GroupInfoBlob {
    GroupInfoBlob::parse(vec![byte; 8]).unwrap()
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
    let sessions = Arc::new(InMemorySessions::default());
    let archive = Arc::new(InMemoryArchive::default());
    let devices = Arc::new(InMemoryKeyDirectory::keyed_by(archive.clone()));
    let notifier = Arc::new(RecordingMlsNotifier::default());
    let federation = Arc::new(RecordingMlsFederation::default());
    let groups = Arc::new(RecordingGroupNotifier::default());
    let reach = Arc::new(StubReachability::default());
    World {
        append: AppendCommit::new(
            accounts.clone(),
            store.clone(),
            delivery.clone(),
            delivery.clone(),
            sessions.clone(),
            devices.clone(),
            notifier.clone(),
            federation.clone(),
        ),
        catch_up: CatchUpCommits::new(accounts.clone(), store.clone(), delivery.clone()),
        load_group_info: LoadGroupInfo::new(accounts.clone(), store.clone(), delivery.clone()),
        claim: ClaimWelcomes::new(delivery.clone()),
        send: SendWelcome::new(
            InstanceOrigin::parse("http://localhost:8080").unwrap(),
            accounts.clone(),
            remote_actors.clone(),
            store.clone(),
            delivery.clone(),
            reach.clone(),
            notifier.clone(),
            federation.clone(),
        ),
        receive_commit: ReceiveCommit::new(
            accounts.clone(),
            remote_actors.clone(),
            store.clone(),
            delivery.clone(),
            delivery.clone(),
            reach.clone(),
            notifier.clone(),
            groups.clone(),
            store.clone(),
        ),
        receive_welcome: ReceiveWelcome::new(
            accounts,
            remote_actors.clone(),
            store.clone(),
            delivery.clone(),
            reach.clone(),
            notifier.clone(),
            groups.clone(),
            store.clone(),
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
        sessions,
        archive,
        devices,
        notifier,
        federation,
        groups,
        reach,
    }
}

impl World {
    /// A live session of `by`'s, naming no device.
    fn bearer(&self, by: &Account) -> Bearer {
        let now = OffsetDateTime::now_utc();
        Bearer {
            user: by.id,
            session: self.sessions.live_at(by.id, now),
            authenticated_at: now,
        }
    }

    async fn commit(&self, by: &Account, at: i64) -> Result<Commit, DeliveryError> {
        self.append
            .execute(
                &self.bearer(by),
                self.group,
                epoch(at),
                commit_blob(at as u8),
                group_info(at as u8),
            )
            .await
    }

    async fn group_info(&self, conversation: ConversationId) -> Option<GroupInfo> {
        self.delivery.newest(conversation).await.unwrap()
    }

    fn incoming(&self, at: i64, info: u8) -> IncomingCommit {
        IncomingCommit {
            recipient: self.alice.id,
            proposer: self.carol.actor_uri.clone(),
            conversation: self.group,
            epoch: epoch(at),
            blob: commit_blob(at as u8),
            group_info: group_info(info),
            roster: None,
        }
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
    let roster = GroupSnapshot::of(
        &w.store.find(w.group).await.unwrap().expect("the group"),
        &w.store.memberships(w.group).await.unwrap(),
    );
    assert_eq!(
        w.federation.sent(),
        vec![SentMls::Commit {
            from: w.alice.actor_uri.clone(),
            to: w.carol.actor_uri.clone(),
            commit,
            group_info: group_info(1),
            roster: Some(roster),
        }]
    );
}

#[tokio::test]
async fn a_dms_commit_travels_without_a_roster() {
    let w = world().await;
    let dm = w
        .store
        .open_dm(&w.alice.actor_uri, &w.carol.actor_uri, None)
        .await
        .unwrap();

    w.append
        .execute(
            &w.bearer(&w.alice),
            dm,
            epoch(1),
            commit_blob(1),
            group_info(1),
        )
        .await
        .unwrap();

    assert!(matches!(
        &w.federation.sent()[..],
        [SentMls::Commit { roster: None, .. }]
    ));
}

#[tokio::test]
async fn a_commit_at_a_taken_epoch_answers_the_one_there() {
    let w = world().await;
    let first = w.commit(&w.alice, 1).await.unwrap();
    let second = w.commit(&w.alice, 2).await.unwrap();

    for (at, winner) in [(2, &second), (1, &first)] {
        let lost = w.commit(&w.bob, at).await;

        assert!(
            matches!(&lost, Err(DeliveryError::EpochTaken(held)) if **held == *winner),
            "epoch {at}: {lost:?}"
        );
    }
    assert_eq!(w.stored(w.group).await, vec![first, second]);
}

#[tokio::test]
async fn a_members_commit_goes_only_at_the_epoch_after_the_latest() {
    let w = world().await;

    for (at, next) in [(0, 1), (2, 1)] {
        let refused = w.commit(&w.alice, at).await;

        assert!(
            matches!(refused, Err(DeliveryError::EpochNotNext(e)) if e == epoch(next)),
            "epoch {at}: {refused:?}"
        );
    }
    let first = w.commit(&w.alice, 1).await.unwrap();
    let ahead = w.commit(&w.bob, 3).await;
    assert!(
        matches!(ahead, Err(DeliveryError::EpochNotNext(e)) if e == epoch(2)),
        "{ahead:?}"
    );
    let second = w.commit(&w.bob, 2).await.unwrap();

    assert_eq!(w.stored(w.group).await, vec![first, second]);
    assert_eq!(w.notifier.committed().len(), 2 * 2, "the stored ones only");
}

#[tokio::test]
async fn a_member_never_commits_into_a_gap_the_mirrored_log_holds() {
    let w = world().await;
    for at in [1, 3] {
        w.receive_commit
            .execute(IncomingCommit {
                recipient: w.alice.id,
                proposer: w.carol.actor_uri.clone(),
                conversation: w.group,
                epoch: epoch(at),
                blob: commit_blob(at as u8),
                group_info: group_info(at as u8),
                roster: None,
            })
            .await
            .unwrap();
    }

    let refused = w.commit(&w.alice, 2).await;

    assert!(
        matches!(refused, Err(DeliveryError::EpochNotNext(e)) if e == epoch(4)),
        "{refused:?}"
    );
    assert_eq!(
        w.stored(w.group)
            .await
            .iter()
            .map(|c| c.epoch)
            .collect::<Vec<_>>(),
        vec![epoch(1), epoch(3)],
        "the epoch 2 still on its way from Carol's instance is the one to fill it"
    );
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
            .execute(
                &w.bearer(&w.alice),
                unknown,
                epoch(at),
                commit_blob(1),
                group_info(1),
            )
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
async fn a_stored_commit_keeps_the_group_info_of_the_epoch_it_opens() {
    let w = world().await;

    w.commit(&w.alice, 1).await.unwrap();
    let first = w.group_info(w.group).await;
    w.commit(&w.bob, 2).await.unwrap();

    assert_eq!(
        first,
        Some(GroupInfo {
            epoch: epoch(1),
            blob: group_info(1)
        })
    );
    assert_eq!(
        w.group_info(w.group).await,
        Some(GroupInfo {
            epoch: epoch(2),
            blob: group_info(2)
        })
    );
    let sent: Vec<_> = w
        .federation
        .sent()
        .into_iter()
        .map(|sent| match sent {
            SentMls::Commit { group_info, .. } => group_info,
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(sent, vec![group_info(1), group_info(2)], "with each commit");
}

#[tokio::test]
async fn a_commit_refused_its_epoch_keeps_no_group_info() {
    let w = world().await;
    w.commit(&w.alice, 1).await.unwrap();

    let taken = w
        .append
        .execute(
            &w.bearer(&w.bob),
            w.group,
            epoch(1),
            commit_blob(7),
            group_info(7),
        )
        .await;
    let ahead = w.commit(&w.bob, 3).await;

    assert!(
        matches!(taken, Err(DeliveryError::EpochTaken(_))),
        "{taken:?}"
    );
    assert!(
        matches!(ahead, Err(DeliveryError::EpochNotNext(_))),
        "{ahead:?}"
    );
    assert_eq!(
        w.group_info(w.group).await,
        Some(GroupInfo {
            epoch: epoch(1),
            blob: group_info(1)
        }),
        "another history's GroupInfo is never kept"
    );
}

impl World {
    /// Alice holds a history key, her laptop approved by its words and a fresh device nobody
    /// approved: a session naming each, and one naming none.
    async fn alice_with_a_history_key(&self) -> (Bearer, Bearer, Bearer) {
        let key = HistoryKey {
            generation: HistoryGeneration::parse(1).unwrap(),
            salt: HistorySalt::parse(&[1; 16]).unwrap(),
            check_value: HistoryCheckValue::parse(&[2; 32]).unwrap(),
            approval_public_key: ApprovalPublicKey::parse(&[3; 32]).unwrap(),
        };
        let now = OffsetDateTime::now_utc();
        let (laptop, fresh) = (DeviceId::generate(), DeviceId::generate());
        for device in [laptop, fresh] {
            self.devices
                .attest(
                    self.alice.id,
                    device,
                    &DeviceLabel::unknown(),
                    None,
                    &Attestation {
                        root_key: DeviceRootKey::parse(&[1; 32]).unwrap(),
                        signature: vec![1; 64],
                        kid: "key-1".to_owned(),
                        issued_at: now,
                        expires_at: now + Duration::days(365),
                    },
                    &HpkeKeyWrite::Clear,
                )
                .await
                .unwrap();
        }
        self.archive
            .replace(self.alice.id, &key, laptop, now)
            .await
            .unwrap();
        self.devices
            .approved_by_words(self.alice.id, laptop, &key)
            .await;
        (
            self.naming(laptop).await,
            self.naming(fresh).await,
            self.bearer(&self.alice),
        )
    }

    /// A live session of Alice's, naming `device`.
    async fn naming(&self, device: DeviceId) -> Bearer {
        let bearer = self.bearer(&self.alice);
        self.sessions
            .link(
                self.alice.id,
                bearer.session,
                device,
                OffsetDateTime::now_utc(),
            )
            .await
            .unwrap();
        bearer
    }
}

#[tokio::test]
async fn a_device_commits_itself_in_only_from_a_session_naming_it_approved() {
    let w = world().await;
    let (on_the_laptop, on_the_fresh_one, unnamed) = w.alice_with_a_history_key().await;
    let external = |bearer| {
        w.append
            .execute(bearer, w.group, epoch(1), external_commit(), group_info(1))
    };

    let from_the_fresh_one = external(&on_the_fresh_one).await;
    let from_no_device = external(&unnamed).await;
    let refused_left = (w.stored(w.group).await, w.group_info(w.group).await);
    let from_the_laptop = external(&on_the_laptop).await;

    assert!(
        matches!(
            from_the_fresh_one,
            Err(DeliveryError::ApprovalRequired(ApprovalRequired))
        ),
        "{from_the_fresh_one:?}"
    );
    assert!(
        matches!(
            from_no_device,
            Err(DeliveryError::DeviceRequired(DeviceRequired))
        ),
        "{from_no_device:?}"
    );
    assert_eq!(refused_left, (Vec::new(), None), "a refusal keeps nothing");
    assert_eq!(from_the_laptop.unwrap().blob, external_commit());
    assert_eq!(w.group_info(w.group).await.map(|i| i.epoch), Some(epoch(1)));
}

#[tokio::test]
async fn only_a_commit_a_client_makes_is_taken_and_nothing_else_kept() {
    let w = world().await;
    let roster = unstamped(
        Some("crew"),
        &[
            member(&w.carol.actor_uri, Role::Admin),
            member(&w.alice.actor_uri, Role::Member),
        ],
    );
    let group = ConversationId::generate();

    for blob in [join_proposal(), CommitBlob::parse(vec![1; 8]).unwrap()] {
        let appended = w
            .append
            .execute(
                &w.bearer(&w.alice),
                w.group,
                epoch(1),
                blob.clone(),
                group_info(1),
            )
            .await;
        let received = w
            .receive_commit
            .execute(IncomingCommit {
                conversation: group,
                blob,
                roster: Some(roster.clone()),
                ..w.incoming(1, 1)
            })
            .await;

        assert!(
            matches!(appended, Err(DeliveryError::NotACommit)),
            "{appended:?}"
        );
        assert!(
            matches!(received, Err(DeliveryError::NotACommit)),
            "{received:?}"
        );
    }
    assert!(w.stored(w.group).await.is_empty());
    assert_eq!(w.group_info(w.group).await, None);
    assert_eq!(
        Conversations::find(&*w.store, group).await.unwrap(),
        None,
        "nor a roster mirrored"
    );
    assert!(w.notifier.committed().is_empty());
    assert!(w.federation.sent().is_empty());
}

#[tokio::test]
async fn a_members_commit_needs_no_device_approved() {
    let w = world().await;
    let (_, on_the_fresh_one, unnamed) = w.alice_with_a_history_key().await;

    for (at, bearer) in [(1, on_the_fresh_one), (2, unnamed)] {
        let committed = w
            .append
            .execute(&bearer, w.group, epoch(at), commit_blob(1), group_info(1))
            .await;

        assert!(committed.is_ok(), "epoch {at}: {committed:?}");
    }
}

#[tokio::test]
async fn an_external_commit_from_outside_the_conversation_is_refused_as_any() {
    let w = world().await;

    let refused = w
        .append
        .execute(
            &w.bearer(&w.dave),
            w.group,
            epoch(1),
            external_commit(),
            group_info(1),
        )
        .await;

    assert!(
        matches!(refused, Err(DeliveryError::NotAMember)),
        "{refused:?}"
    );
}

#[tokio::test]
async fn an_inbound_commit_keeps_its_group_info_only_when_stored_and_newer() {
    let w = world().await;

    w.receive_commit.execute(w.incoming(3, 3)).await.unwrap();
    w.receive_commit.execute(w.incoming(2, 2)).await.unwrap();
    let after_the_older = w.group_info(w.group).await;
    w.receive_commit.execute(w.incoming(4, 9)).await.unwrap();
    w.receive_commit.execute(w.incoming(4, 4)).await.unwrap();

    assert_eq!(
        after_the_older,
        Some(GroupInfo {
            epoch: epoch(3),
            blob: group_info(3)
        }),
        "a delivery arriving late keeps the newer"
    );
    assert_eq!(
        w.group_info(w.group).await,
        Some(GroupInfo {
            epoch: epoch(4),
            blob: group_info(9)
        }),
        "a commit already at its epoch keeps nothing"
    );
}

#[tokio::test]
async fn an_inbound_external_commit_is_taken_as_any_its_instance_decided() {
    let w = world().await;

    w.receive_commit
        .execute(IncomingCommit {
            blob: external_commit(),
            ..w.incoming(1, 1)
        })
        .await
        .unwrap();

    assert_eq!(w.stored(w.group).await.len(), 1);
}

#[tokio::test]
async fn a_member_reads_the_newest_group_info_once_the_group_has_one() {
    let w = world().await;
    let before = w.load_group_info.execute(w.bob.id, w.group).await;
    for at in 1..=2 {
        w.commit(&w.alice, at).await.unwrap();
    }

    let read = w.load_group_info.execute(w.bob.id, w.group).await.unwrap();
    let outsider = w.load_group_info.execute(w.dave.id, w.group).await;
    let unknown = w
        .load_group_info
        .execute(w.bob.id, ConversationId::generate())
        .await;

    assert!(
        matches!(before, Err(DeliveryError::NoGroupInfo)),
        "{before:?}"
    );
    assert_eq!(
        read,
        GroupInfo {
            epoch: epoch(2),
            blob: group_info(2)
        }
    );
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
    let roster = GroupSnapshot::of(
        &w.store.find(w.group).await.unwrap().expect("the group"),
        &w.store.memberships(w.group).await.unwrap(),
    );
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
        .remove_member(w.group, &w.bob.actor_uri, None, None)
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
        recipient: w.alice.id,
        proposer: proposer.clone(),
        conversation,
        epoch: epoch(9),
        blob: commit_blob(9),
        group_info: group_info(9),
        roster: None,
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
        recipient: w.alice.id,
        proposer: w.carol.actor_uri.clone(),
        conversation: w.group,
        epoch: epoch(5),
        blob: commit_blob(5),
        group_info: group_info(5),
        roster: None,
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
    let roster = unstamped(
        Some("crew"),
        &[
            member(&w.carol.actor_uri, Role::Admin),
            member(&w.alice.actor_uri, Role::Member),
        ],
    );

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
    let lines: Vec<_> = w
        .groups
        .events()
        .into_iter()
        .map(|(to, named)| {
            (
                to,
                named.event.kind_name(),
                named.event.by.clone(),
                named.event.subject().cloned(),
            )
        })
        .collect();
    assert_eq!(
        lines,
        vec![(
            w.alice.id,
            "added",
            w.carol.actor_uri.clone(),
            Some(w.alice.actor_uri.clone())
        )],
        "the Welcome's sender added her: once"
    );
}

/// Each line recorded, by whom it names, as the account `to` is told it.
fn lines_told(w: &World, to: UserId) -> Vec<(String, Option<ActorUri>)> {
    w.groups
        .events()
        .into_iter()
        .filter(|(told, _)| *told == to)
        .map(|(_, named)| {
            (
                named.event.kind_name().to_owned(),
                named.event.subject().cloned(),
            )
        })
        .collect()
}

#[tokio::test]
async fn a_roster_brings_in_every_member_here_it_lists_and_announces_each_once() {
    let w = world().await;
    let group = ConversationId::generate();
    let roster = unstamped(
        Some("crew"),
        &[
            member(&w.carol.actor_uri, Role::Admin),
            member(&w.alice.actor_uri, Role::Member),
            member(&w.bob.actor_uri, Role::Member),
        ],
    );

    // A Welcome reaches each member's inbox on its own; whichever comes first brings both in.
    for recipient in [w.alice.id, w.bob.id, w.alice.id] {
        w.receive_welcome
            .execute(IncomingWelcome {
                recipient,
                ..w.incoming_welcome(&w.carol.actor_uri, group, Some(roster.clone()))
            })
            .await
            .unwrap();
    }

    let mut joined = w.groups.sent();
    joined.sort_by_key(|notice| format!("{notice:?}"));
    let mut expected = vec![
        GroupNotice::Joined(w.alice.id, group, w.carol.actor_uri.clone()),
        GroupNotice::Joined(w.bob.id, group, w.carol.actor_uri.clone()),
    ];
    expected.sort_by_key(|notice| format!("{notice:?}"));
    assert_eq!(joined, expected);
    let added = |who: &Account| ("added".to_owned(), Some(who.actor_uri.clone()));
    for to in [w.alice.id, w.bob.id] {
        let mut lines = lines_told(&w, to);
        lines.sort_by_key(|line| format!("{line:?}"));
        let mut expected = vec![added(&w.alice), added(&w.bob)];
        expected.sort_by_key(|line| format!("{line:?}"));
        assert_eq!(lines, expected, "each one's line, once");
    }
}

#[tokio::test]
async fn a_roster_leaves_out_a_member_here_who_does_not_admit_its_sender() {
    for keeps_out in ["the setting", "a block of someone listed"] {
        let w = world().await;
        let group = ConversationId::generate();
        match keeps_out {
            "the setting" => w
                .reach
                .set(w.bob.id, &w.carol.actor_uri, KEPT_OUT_BY_THE_SETTING),
            _ => w.reach.set(w.bob.id, &w.eve.actor_uri, BLOCKED),
        }
        let roster = unstamped(
            Some("crew"),
            &[
                member(&w.carol.actor_uri, Role::Admin),
                member(&w.alice.actor_uri, Role::Member),
                member(&w.bob.actor_uri, Role::Member),
                member(&w.eve.actor_uri, Role::Member),
            ],
        );

        w.receive_welcome
            .execute(w.incoming_welcome(&w.carol.actor_uri, group, Some(roster)))
            .await
            .unwrap();

        let members = w.store.members(group).await.unwrap();
        assert!(
            !members.iter().any(|m| m.actor_uri == w.bob.actor_uri),
            "kept out by {keeps_out}"
        );
        assert_eq!(members.len(), 3, "carol, alice and eve");
        assert_eq!(
            w.groups.sent(),
            vec![GroupNotice::Joined(
                w.alice.id,
                group,
                w.carol.actor_uri.clone()
            )]
        );
        assert!(lines_told(&w, w.bob.id).is_empty());
    }
}

#[tokio::test]
async fn a_welcome_from_before_the_recipients_departure_is_refused_and_brings_nobody_back() {
    let w = world().await;
    let group = ConversationId::generate();
    let roster = unstamped(
        Some("crew"),
        &[
            member(&w.carol.actor_uri, Role::Admin),
            member(&w.alice.actor_uri, Role::Member),
        ],
    );
    w.receive_welcome
        .execute(w.incoming_welcome(&w.carol.actor_uri, group, Some(roster.clone())))
        .await
        .unwrap();
    w.store
        .remove_member(group, &w.alice.actor_uri, None, None)
        .await
        .unwrap();

    let refused = w
        .receive_welcome
        .execute(w.incoming_welcome(&w.carol.actor_uri, group, Some(roster)))
        .await;

    assert!(
        matches!(refused, Err(DeliveryError::RecipientNotAMember)),
        "{refused:?}"
    );
    assert_eq!(w.store.members(group).await.unwrap().len(), 1);
    assert_eq!(w.notifier.welcomes_ready().len(), 1, "only the first one");
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
            Some(unstamped(Some("crew"), &[])),
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
    let roster = unstamped(Some("crew"), &[member(&w.alice.actor_uri, Role::Member)]);
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
    unstamped(
        Some("crew"),
        &[
            member(&w.carol.actor_uri, Role::Admin),
            member(&w.alice.actor_uri, Role::Member),
        ],
    )
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
    let roster = unstamped(
        Some("crew"),
        &[
            member(&w.alice.actor_uri, Role::Admin),
            member(&w.bob.actor_uri, Role::Member),
            member(&w.carol.actor_uri, Role::Member),
        ],
    );

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

/// The commit adding someone is sent before their Welcome, and may arrive first: it holds the group
/// then, or the members who joined before it could never catch up on it.
#[tokio::test]
async fn an_inbound_commit_that_outruns_the_welcome_mirrors_the_group_and_is_stored() {
    let w = world().await;
    let group = ConversationId::generate();
    let roster = unstamped(
        Some("crew"),
        &[
            member(&w.carol.actor_uri, Role::Admin),
            member(&w.alice.actor_uri, Role::Member),
        ],
    );

    w.receive_commit
        .execute(IncomingCommit {
            recipient: w.alice.id,
            proposer: w.carol.actor_uri.clone(),
            conversation: group,
            epoch: epoch(1),
            blob: commit_blob(1),
            group_info: group_info(1),
            roster: Some(roster.clone()),
        })
        .await
        .unwrap();
    w.receive_welcome
        .execute(w.incoming_welcome(&w.carol.actor_uri, group, Some(roster)))
        .await
        .unwrap();

    assert_eq!(w.stored(group).await.len(), 1);
    assert_eq!(w.store.members(group).await.unwrap().len(), 2);
    assert_eq!(
        w.groups.sent(),
        vec![GroupNotice::Joined(
            w.alice.id,
            group,
            w.carol.actor_uri.clone()
        )]
    );
    let lines: Vec<_> = w
        .groups
        .events()
        .into_iter()
        .map(|(to, named)| (to, named.event.kind_name(), named.event.by.clone()))
        .collect();
    assert_eq!(
        lines,
        vec![(w.alice.id, "added", w.carol.actor_uri.clone())],
        "once, though the Welcome came after"
    );
    assert_eq!(w.notifier.welcomes_ready().len(), 1);
}

#[tokio::test]
async fn an_inbound_commit_that_would_bring_someone_in_from_who_they_do_not_admit_is_dropped() {
    for kept_out in [BLOCKED, KEPT_OUT_BY_THE_SETTING] {
        let w = world().await;
        let group = ConversationId::generate();
        w.reach.set(w.alice.id, &w.carol.actor_uri, kept_out);

        let dropped = w
            .receive_commit
            .execute(IncomingCommit {
                recipient: w.alice.id,
                proposer: w.carol.actor_uri.clone(),
                conversation: group,
                epoch: epoch(1),
                blob: commit_blob(1),
                group_info: group_info(1),
                roster: Some(crew_with_alice(&w)),
            })
            .await;

        assert!(dropped.is_ok(), "{dropped:?}");
        assert_eq!(Conversations::find(&*w.store, group).await.unwrap(), None);
        assert!(w.stored(group).await.is_empty());
        assert_eq!(w.group_info(group).await, None);
        assert!(w.groups.sent().is_empty());
    }
}
