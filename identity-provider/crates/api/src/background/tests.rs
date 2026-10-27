use std::sync::atomic::{AtomicUsize, Ordering};

use domain::auth::testing::{
    InMemoryPasswordResets, InMemorySessions, InMemorySignInAccounts, RecordingMailer,
    RecordingTickets, signed_up,
};
use domain::auth::{AuthError, Registrations, ResetMail, ResetMailer};
use domain::identity::InstanceOrigin;

use super::*;

#[tokio::test(start_paused = true)]
async fn a_timer_runs_at_once_then_every_period_until_stopped() {
    let (runs, stop) = (Arc::new(AtomicUsize::new(0)), CancellationToken::new());
    let timer = tokio::spawn({
        let (runs, stop) = (runs.clone(), stop.clone());
        async move {
            every(Duration::from_secs(60), stop, || async {
                runs.fetch_add(1, Ordering::SeqCst);
            })
            .await
        }
    });

    tokio::time::sleep(Duration::from_secs(150)).await;
    stop.cancel();
    timer.await.unwrap();

    assert_eq!(runs.load(Ordering::SeqCst), 3, "at 0, 60 and 120 s");
}

#[tokio::test(start_paused = true)]
async fn a_run_under_way_finishes_before_the_timer_stops() {
    let (finished, stop) = (Arc::new(AtomicUsize::new(0)), CancellationToken::new());
    let timer = tokio::spawn({
        let (finished, stop) = (finished.clone(), stop.clone());
        async move {
            every(Duration::from_secs(60), stop, || async {
                tokio::time::sleep(Duration::from_secs(5)).await;
                finished.fetch_add(1, Ordering::SeqCst);
            })
            .await
        }
    });

    tokio::time::sleep(Duration::from_secs(1)).await;
    stop.cancel();
    timer.await.unwrap();

    assert_eq!(finished.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_relay_stops_even_while_its_stream_is_silent() {
    let stop = CancellationToken::new();
    let mut silent: BoxStream<'static, u8> = futures_util::stream::pending().boxed();
    let waiting = tokio::spawn({
        let stop = stop.clone();
        async move { next(&mut silent, &stop).await }
    });

    stop.cancel();

    assert_eq!(waiting.await.unwrap(), None);
}

/// The use case over fakes holding `names`' accounts, mailing through `mailer`.
fn requesting_through(names: &[&str], mailer: Arc<dyn ResetMailer>) -> Arc<RequestPasswordReset> {
    let accounts = Arc::new(InMemorySignInAccounts::with(
        names.iter().map(|name| signed_up(name)),
    ));
    let resets = Arc::new(InMemoryPasswordResets::over(
        accounts.clone(),
        Arc::new(InMemorySessions::default()),
        Arc::new(RecordingTickets::default()),
    ));
    Arc::new(RequestPasswordReset::new(
        Registrations::Open,
        InstanceOrigin::parse("http://localhost:8080").unwrap(),
        "Aotearoa".to_owned(),
        accounts,
        resets,
        mailer,
    ))
}

/// The use case over fakes holding `names`' accounts, and the mail it sends.
fn requesting(names: &[&str]) -> (Arc<RequestPasswordReset>, Arc<RecordingMailer>) {
    let mailer = Arc::new(RecordingMailer::default());
    (requesting_through(names, mailer.clone()), mailer)
}

fn address(name: &str) -> Email {
    Email::parse(&format!("{name}@idp.test")).unwrap()
}

/// Panics at the first address, then mails as `RecordingMailer` does.
#[derive(Default)]
struct PanickingOnce {
    panicked: std::sync::atomic::AtomicBool,
    mailed: RecordingMailer,
}

#[async_trait::async_trait]
impl ResetMailer for PanickingOnce {
    async fn send_reset_link(&self, mail: &ResetMail) -> Result<(), AuthError> {
        if !self.panicked.swap(true, Ordering::SeqCst) {
            panic!("a mailer gone wrong");
        }
        self.mailed.send_reset_link(mail).await
    }
}

/// Never answers, as a relay that stalls.
struct Stalled;

#[async_trait::async_trait]
impl ResetMailer for Stalled {
    async fn send_reset_link(&self, _: &ResetMail) -> Result<(), AuthError> {
        std::future::pending().await
    }
}

#[tokio::test]
async fn the_reset_links_asked_for_are_mailed_one_request_after_the_other() {
    let (request, mailer) = requesting(&["alice", "bob"]);
    let (requests, queue) = reset_requests();
    let served = CancellationToken::new();
    let worker = tokio::spawn(serve_reset_requests(
        queue,
        request,
        served.clone(),
        CancellationToken::new(),
    ));

    for name in ["alice", "nobody", "bob"] {
        requests.submit(address(name));
    }
    tokio::time::timeout(Duration::from_secs(5), async {
        while mailer.reset_mails().len() < 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("mailed in the background");
    served.cancel();
    worker.await.unwrap();

    let mailed: Vec<String> = mailer
        .reset_mails()
        .into_iter()
        .map(|mail| mail.to)
        .collect();
    assert_eq!(mailed, vec!["alice@idp.test", "bob@idp.test"]);
}

#[tokio::test]
async fn the_requests_still_waiting_once_the_server_has_answered_are_mailed() {
    let (request, mailer) = requesting(&["alice", "bob", "carol"]);
    let (requests, queue) = reset_requests();
    for name in ["alice", "bob", "carol"] {
        requests.submit(address(name));
    }
    let served = CancellationToken::new();
    served.cancel();

    serve_reset_requests(queue, request, served, CancellationToken::new()).await;

    assert_eq!(mailer.reset_mails().len(), 3);
}

/// Cancels `out_of_time` ten seconds on, as the instance's stop does.
fn ten_seconds_on(out_of_time: &CancellationToken) {
    let out_of_time = out_of_time.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(10)).await;
        out_of_time.cancel();
    });
}

#[tokio::test(start_paused = true)]
async fn a_stalled_relay_holds_the_stop_up_no_longer_than_the_instances_deadline() {
    let request = requesting_through(&["alice", "bob"], Arc::new(Stalled));
    let (requests, mut queue) = reset_requests();
    for name in ["alice", "bob"] {
        requests.submit(address(name));
    }
    let (served, out_of_time) = (CancellationToken::new(), CancellationToken::new());
    served.cancel();
    let started = tokio::time::Instant::now();
    ten_seconds_on(&out_of_time);

    let unsent = take_reset_requests(&mut queue, &request, &served, &out_of_time).await;

    assert_eq!(started.elapsed(), Duration::from_secs(10));
    assert_eq!(unsent, 2, "alice's under way, bob's waiting");
}

#[tokio::test(start_paused = true)]
async fn an_idle_worker_cut_by_the_deadline_leaves_nothing_unsent() {
    let (request, _) = requesting(&["alice"]);
    let (_requests, mut queue) = reset_requests();
    let (served, out_of_time) = (CancellationToken::new(), CancellationToken::new());
    ten_seconds_on(&out_of_time);

    let unsent = take_reset_requests(&mut queue, &request, &served, &out_of_time).await;

    assert_eq!(unsent, 0);
}

#[tokio::test]
async fn a_request_that_panics_leaves_the_worker_taking_the_next() {
    let mailer = Arc::new(PanickingOnce::default());
    let request = requesting_through(&["alice", "bob"], mailer.clone());
    let (requests, queue) = reset_requests();
    let served = CancellationToken::new();
    let worker = tokio::spawn(serve_reset_requests(
        queue,
        request,
        served.clone(),
        CancellationToken::new(),
    ));

    requests.submit(address("alice"));
    requests.submit(address("bob"));
    tokio::time::timeout(Duration::from_secs(5), async {
        while mailer.mailed.reset_mails().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("bob's mailed after alice's panicked");
    served.cancel();
    worker.await.expect("the worker itself never panicked");

    let mailed: Vec<String> = mailer
        .mailed
        .reset_mails()
        .into_iter()
        .map(|mail| mail.to)
        .collect();
    assert_eq!(mailed, vec!["bob@idp.test"]);
}

#[tokio::test]
async fn a_full_queue_drops_a_request_rather_than_wait() {
    let (request, mailer) = requesting(&["alice"]);
    let (requests, mut queue) = reset_requests();
    for _ in 0..RESET_REQUESTS_QUEUED {
        requests.submit(address("nobody"));
    }

    requests.submit(address("alice"));
    queue.drain(&request).await;

    assert!(mailer.reset_mails().is_empty(), "alice's came too late");
}

#[tokio::test]
async fn a_flood_of_made_up_addresses_never_stops_a_real_ones_mail() {
    let (request, mailer) = requesting(&["alice"]);
    let (requests, queue) = reset_requests();
    let served = CancellationToken::new();
    let worker = tokio::spawn(serve_reset_requests(
        queue,
        request,
        served.clone(),
        CancellationToken::new(),
    ));

    for n in 0..1_000 {
        requests.submit(address(&format!("nobody{n}")));
        if n % 100 == 0 {
            tokio::task::yield_now().await;
        }
    }
    requests.submit(address("alice"));
    tokio::time::timeout(Duration::from_secs(5), async {
        while mailer.reset_mails().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("alice's mailed");
    served.cancel();
    worker.await.unwrap();

    let mailed: Vec<String> = mailer
        .reset_mails()
        .into_iter()
        .map(|mail| mail.to)
        .collect();
    assert_eq!(mailed, vec!["alice@idp.test"]);
}

/// Refuses every mail, as a spent budget does.
struct Spent;

#[async_trait::async_trait]
impl ResetMailer for Spent {
    async fn send_reset_link(&self, _: &ResetMail) -> Result<(), AuthError> {
        Err(AuthError::MailBudgetSpent)
    }
}

#[tokio::test]
async fn mails_the_budget_refuses_leave_the_worker_taking_requests() {
    let request = requesting_through(&["alice", "bob"], Arc::new(Spent));
    let (requests, mut queue) = reset_requests();
    for name in ["alice", "bob"] {
        requests.submit(address(name));
    }
    let served = CancellationToken::new();
    served.cancel();

    let unsent =
        take_reset_requests(&mut queue, &request, &served, &CancellationToken::new()).await;

    assert_eq!(unsent, 0);
    assert_eq!(queue.queue.len(), 0, "both taken");
}

#[test]
fn a_burst_is_warned_about_once_then_its_last_count_a_minute_on() {
    let start = Instant::now();
    let mut tally = Tally::default();

    let first = tally.add(start);
    let rest: Vec<Option<usize>> = (1..=30)
        .map(|second| tally.add(start + Duration::from_secs(second)))
        .collect();
    let too_soon = tally.due(start + Duration::from_secs(59));
    let a_minute_on = tally.due(start + Duration::from_secs(60));
    let nothing_left = tally.due(start + Duration::from_secs(600));

    assert_eq!(first, Some(1));
    assert!(rest.iter().all(Option::is_none), "{rest:?}");
    assert_eq!(too_soon, None);
    assert_eq!(a_minute_on, Some(30), "the burst's last count");
    assert_eq!(nothing_left, None);
}

#[test]
fn a_tally_warns_at_most_once_a_minute() {
    let start = Instant::now();
    let mut tally = Tally::default();

    let warned: Vec<bool> = (0..180)
        .map(|second| tally.add(start + Duration::from_secs(second)).is_some())
        .collect();

    let at: Vec<usize> = warned
        .iter()
        .enumerate()
        .filter_map(|(second, warned)| warned.then_some(second))
        .collect();
    assert_eq!(at, vec![0, 60, 120]);
}
