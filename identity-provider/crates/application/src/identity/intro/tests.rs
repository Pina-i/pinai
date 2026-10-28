use domain::auth::testing::{
    InMemoryPasswordResets, InMemorySessions, InMemorySignInAccounts, RecordingMailer,
    RecordingTickets, signed_up,
};
use std::sync::atomic::{AtomicBool, Ordering};

use domain::auth::{Registrations, SignInAccount};
use domain::identity::testing::{InMemoryAccounts, InMemorySavedIntro};
use domain::identity::{PINAI_SOURCE_URL, SavedIntroError, SourceUrl};
use tokio::sync::Notify;

use crate::auth::RequestPasswordReset;
use crate::identity::DescribeInstance;

use super::*;

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap()
}

fn text(name: Option<&str>, description: Option<&str>) -> IntroText {
    IntroText::parse(name, description).unwrap()
}

fn draft(name: Option<&str>, description: Option<&str>) -> Result<IntroDraft, ValidationError> {
    Ok(IntroDraft {
        name: name.map(str::to_owned),
        description: description.map(str::to_owned),
    })
}

/// What a request that carried no draft hands the use case.
fn no_draft() -> Result<IntroDraft, ValidationError> {
    Err(ValidationError::new("body", "no draft"))
}

struct World {
    admin: SignInAccount,
    member: SignInAccount,
    accounts: Arc<InMemorySignInAccounts>,
    saved: Arc<InMemorySavedIntro>,
    in_force: Arc<IntroInForce>,
    mailer: Arc<RecordingMailer>,
    show: ShowIntro,
    edit: EditIntro,
    describe: DescribeInstance,
    request_reset: RequestPasswordReset,
}

/// An open instance whose `.env` names it Aotearoa, and nobody saved a text yet.
fn world() -> World {
    let admin = SignInAccount {
        admin: true,
        ..signed_up("root")
    };
    let member = signed_up("alice");
    let accounts = Arc::new(InMemorySignInAccounts::with([
        admin.clone(),
        member.clone(),
    ]));
    let origin = InstanceOrigin::parse("http://localhost:8080").unwrap();
    let saved = Arc::new(InMemorySavedIntro::default());
    let in_force = Arc::new(IntroInForce::new(
        origin.clone(),
        text(Some("Aotearoa"), Some("Design people.")),
    ));
    let mailer = Arc::new(RecordingMailer::default());
    let resets = Arc::new(InMemoryPasswordResets::over(
        accounts.clone(),
        Arc::new(InMemorySessions::default()),
        Arc::new(RecordingTickets::default()),
    ));
    World {
        show: ShowIntro::new(accounts.clone(), in_force.clone()),
        edit: EditIntro::new(accounts.clone(), saved.clone(), in_force.clone()),
        describe: DescribeInstance::new(
            in_force.clone(),
            SourceUrl::parse(PINAI_SOURCE_URL).unwrap(),
            Registrations::Open,
            Arc::new(InMemoryAccounts::default()),
        ),
        request_reset: RequestPasswordReset::new(
            Registrations::Open,
            origin,
            in_force.clone(),
            accounts.clone(),
            resets,
            mailer.clone(),
        ),
        accounts,
        admin,
        member,
        saved,
        in_force,
        mailer,
    }
}

#[tokio::test]
async fn a_member_is_refused_before_anything_whatever_they_send() {
    let w = world();
    let long = "ō".repeat(41);

    for (caller, sent) in [
        (w.member.id, draft(Some("Kāinga"), None)),
        (w.member.id, draft(Some(&long), None)),
        (w.member.id, no_draft()),
        (UserId::generate(), draft(Some("Kāinga"), None)),
    ] {
        let edited = w.edit.execute(caller, sent, now()).await;

        assert!(matches!(edited, Err(IntroError::NotAdmin)), "{edited:?}");
    }
    assert_eq!(w.saved.saved(), None, "nothing saved");
    assert_eq!(
        w.in_force.text(),
        text(Some("Aotearoa"), Some("Design people."))
    );
}

#[tokio::test]
async fn a_field_past_its_limit_is_refused_and_nothing_saved() {
    let w = world();
    let long = "ō".repeat(91);

    let edited = w
        .edit
        .execute(w.admin.id, draft(Some("Kāinga"), Some(&long)), now())
        .await;

    let Err(IntroError::Invalid(broken)) = edited else {
        panic!("{edited:?}");
    };
    assert_eq!(broken.field, "instance description");
    assert_eq!(w.saved.saved(), None);
    assert_eq!(w.in_force.shown().name(), "Aotearoa");
}

#[tokio::test]
async fn a_request_carrying_no_draft_is_refused_once_the_caller_is_an_admin() {
    let w = world();

    let edited = w.edit.execute(w.admin.id, no_draft(), now()).await;

    let Err(IntroError::Invalid(broken)) = edited else {
        panic!("{edited:?}");
    };
    assert_eq!(broken.to_string(), "body: no draft");
    assert_eq!(w.saved.saved(), None);
}

#[tokio::test]
async fn a_text_saved_shows_at_once_on_the_pages_and_in_the_next_reset_mail() {
    let w = world();

    let edited = w
        .edit
        .execute(w.admin.id, draft(Some("  Kāinga "), Some(" ")), now())
        .await
        .unwrap();

    assert_eq!(edited, text(Some("Kāinga"), None));
    assert_eq!(w.saved.saved(), Some((edited, w.admin.id, now())));
    let facts = w.describe.execute(now()).await.unwrap();
    assert_eq!((facts.name.as_str(), facts.description), ("Kāinga", None));
    let address = w.request_reset.accept(&w.member.email).unwrap();
    w.request_reset.execute(&address, now()).await.unwrap();
    assert_eq!(w.mailer.reset_mails()[0].instance, "Kāinga");
}

#[tokio::test]
async fn a_save_that_fails_leaves_the_text_in_force_as_it_was() {
    let w = world();
    w.saved.break_down();

    let edited = w
        .edit
        .execute(w.admin.id, draft(Some("Kāinga"), None), now())
        .await;

    assert!(
        matches!(edited, Err(IntroError::Unexpected(_))),
        "{edited:?}"
    );
    let facts = w.describe.execute(now()).await.unwrap();
    assert_eq!(facts.name, "Aotearoa");
    assert_eq!(facts.description.as_deref(), Some("Design people."));
}

#[tokio::test]
async fn an_admin_is_shown_the_text_as_written_a_default_name_as_none() {
    let w = world();
    w.edit
        .execute(w.admin.id, draft(None, Some("Weavers.")), now())
        .await
        .unwrap();

    let shown = w.show.execute(w.admin.id).await.unwrap();

    assert_eq!(shown, text(None, Some("Weavers.")));
    assert_eq!(
        w.in_force.shown().name(),
        "localhost:8080",
        "the pages' default"
    );
}

#[tokio::test]
async fn only_an_admin_is_shown_the_text() {
    let w = world();

    let shown = w.show.execute(w.member.id).await;

    assert!(matches!(shown, Err(IntroError::NotAdmin)), "{shown:?}");
}

/// Writes the row at each save, but holds the first one open until released.
#[derive(Default)]
struct HeldFirstSave {
    row: std::sync::Mutex<Option<IntroText>>,
    held: AtomicBool,
    written: Notify,
    release: Notify,
}

#[async_trait::async_trait]
impl SavedIntro for HeldFirstSave {
    async fn get(&self) -> Result<Option<IntroText>, SavedIntroError> {
        Ok(self.row.lock().unwrap().clone())
    }

    async fn save(
        &self,
        text: &IntroText,
        _: UserId,
        _: OffsetDateTime,
    ) -> Result<(), SavedIntroError> {
        *self.row.lock().unwrap() = Some(text.clone());
        if !self.held.swap(true, Ordering::SeqCst) {
            self.written.notify_one();
            self.release.notified().await;
        }
        Ok(())
    }
}

#[tokio::test(start_paused = true)]
async fn two_admins_saving_at_once_leave_the_row_and_memory_on_the_same_text() {
    let w = world();
    let saves = Arc::new(HeldFirstSave::default());
    let edit = EditIntro::new(w.accounts.clone(), saves.clone(), w.in_force.clone());

    let (first, second, ()) = tokio::join!(
        edit.execute(w.admin.id, draft(Some("Kāinga"), None), now()),
        async {
            saves.written.notified().await;
            edit.execute(w.admin.id, draft(Some("Te Whare"), None), now())
                .await
        },
        async {
            // Paused, the clock moves on once both saves are stuck or done.
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            saves.release.notify_one();
        },
    );

    first.unwrap();
    second.unwrap();
    assert_eq!(saves.get().await.unwrap(), Some(w.in_force.text()));
}
