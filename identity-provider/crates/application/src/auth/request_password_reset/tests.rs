use domain::auth::testing::signed_up;
use domain::auth::{
    OpenReset, PasswordResets, RESET_REQUEST_LIMIT, RESET_TTL, ResetBy, ResetToken, SignInAccount,
};
use time::Duration;

use crate::auth::world::{World, invite_only, now, world};

use super::*;

/// The token of a mailed link, as the link carries it.
fn token_of(mail: &ResetMail) -> ResetToken {
    let token = mail
        .link
        .strip_prefix("http://localhost:8080/r/")
        .unwrap_or_else(|| panic!("{}", mail.link));
    ResetToken::parse(token).unwrap()
}

async fn ask(w: &World, address: &str) -> Result<(), AuthError> {
    let address = w.request_reset.accept(address)?;
    w.request_reset.execute(&address, now()).await
}

#[tokio::test]
async fn whoever_asks_with_an_accounts_address_is_mailed_a_link_open_thirty_minutes() {
    let w = world().await;

    ask(&w, "alice@idp.test").await.unwrap();

    let mails = w.mailer.reset_mails();
    assert_eq!(mails.len(), 1, "{mails:?}");
    let mail = &mails[0];
    assert_eq!(
        (mail.to.as_str(), mail.name.as_str(), mail.instance.as_str()),
        ("alice@idp.test", "alice", "Aotearoa")
    );
    assert_eq!(mail.valid_for, Duration::minutes(30));
    assert_eq!(
        w.resets.find_open(&token_of(mail), now()).await.unwrap(),
        Some(OpenReset {
            member: w.alice.id,
            display_name: Some("alice".to_owned()),
            email: "alice@idp.test".to_owned(),
            by: ResetBy::Mailbox,
            expires_at: now() + Duration::minutes(30),
        })
    );
    assert!(
        w.resets
            .find_open(&token_of(mail), now() + Duration::minutes(30))
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn the_address_is_found_whatever_its_case() {
    let w = world().await;

    ask(&w, "  Alice@IDP.test ").await.unwrap();

    assert_eq!(w.mailer.reset_mails().len(), 1);
}

#[tokio::test]
async fn an_admitted_account_and_an_admin_are_mailed_a_link_too() {
    let w = world().await;
    let admitted = SignInAccount {
        email_verified: false,
        admitted: true,
        ..signed_up("hoku")
    };
    w.sign_up(&admitted).await;
    let admin = w.an_admin().await;

    ask(&w, &admitted.email).await.unwrap();
    ask(&w, &admin.email).await.unwrap();

    let mailed: Vec<String> = w
        .mailer
        .reset_mails()
        .into_iter()
        .map(|mail| mail.to)
        .collect();
    assert_eq!(mailed, vec![admitted.email, admin.email]);
}

#[tokio::test]
async fn no_account_one_still_to_confirm_and_one_past_the_limit_get_the_same_outcome_and_no_mail() {
    let w = world().await;
    let signing_up = SignInAccount {
        email_verified: false,
        ..signed_up("bob")
    };
    w.sign_up(&signing_up).await;
    for _ in 0..RESET_REQUEST_LIMIT {
        ask(&w, "alice@idp.test").await.unwrap();
    }
    let mailed = w.mailer.reset_mails().len();

    let outcomes = [
        ask(&w, "nobody@idp.test").await,
        ask(&w, &signing_up.email).await,
        ask(&w, "alice@idp.test").await,
    ];

    assert_eq!(mailed, RESET_REQUEST_LIMIT);
    for outcome in outcomes {
        assert!(matches!(outcome, Ok(())), "{outcome:?}");
    }
    assert_eq!(w.mailer.reset_mails().len(), mailed, "nothing more mailed");
}

#[tokio::test]
async fn past_five_links_an_hour_the_last_one_mailed_keeps_working() {
    let w = world().await;
    for _ in 0..RESET_REQUEST_LIMIT {
        ask(&w, "alice@idp.test").await.unwrap();
    }
    let last = w.mailer.reset_mails().pop().unwrap();

    ask(&w, "alice@idp.test").await.unwrap();

    assert!(
        w.resets
            .find_open(&token_of(&last), now())
            .await
            .unwrap()
            .is_some()
    );
    let later = now() + Duration::hours(1) + Duration::seconds(1);
    w.request_reset
        .execute(&Email::parse("alice@idp.test").unwrap(), later)
        .await
        .unwrap();
    assert_eq!(
        w.mailer.reset_mails().len(),
        RESET_REQUEST_LIMIT + 1,
        "an hour on"
    );
}

#[tokio::test]
async fn a_request_replaces_the_open_link_an_admins_included() {
    let w = world().await;
    let admin = w.an_admin().await;
    let admins = w
        .resets
        .issue(w.alice.id, admin.id, now(), now() + RESET_TTL)
        .await
        .unwrap();
    ask(&w, "alice@idp.test").await.unwrap();
    let first = token_of(&w.mailer.reset_mails()[0]);

    ask(&w, "alice@idp.test").await.unwrap();

    let second = token_of(&w.mailer.reset_mails()[1]);
    assert_eq!(w.resets.find_open(&admins, now()).await.unwrap(), None);
    assert_eq!(w.resets.find_open(&first, now()).await.unwrap(), None);
    assert!(w.resets.find_open(&second, now()).await.unwrap().is_some());
}

#[tokio::test]
async fn an_invite_only_instance_takes_no_request_and_mails_nothing() {
    let w = invite_only().await;

    let accepted = w.request_reset.accept("alice@idp.test");
    let executed = w
        .request_reset
        .execute(&Email::parse("alice@idp.test").unwrap(), now())
        .await;

    assert!(
        matches!(accepted, Err(AuthError::NoResetByMail)),
        "{accepted:?}"
    );
    assert!(
        matches!(executed, Err(AuthError::NoResetByMail)),
        "{executed:?}"
    );
    assert!(w.mailer.reset_mails().is_empty());
}

#[tokio::test]
async fn what_is_no_address_is_refused_before_any_answer() {
    let w = world().await;

    for typed in ["", "alice", "alice@", "@idp.test"] {
        let accepted = w.request_reset.accept(typed);

        assert!(matches!(accepted, Err(AuthError::BadEmail(_))), "{typed}");
    }
}

#[tokio::test]
async fn a_link_whose_mail_fails_is_taken_back_and_counts_for_nothing() {
    let w = world().await;
    w.mailer.break_down();

    let mut asked = Vec::new();
    for _ in 0..=RESET_REQUEST_LIMIT {
        asked.push(ask(&w, "alice@idp.test").await);
    }

    // Past the limit a request mails nothing and is `Ok`: each of these tried to mail.
    for failed in asked {
        assert!(
            matches!(failed, Err(AuthError::Unexpected(_))),
            "{failed:?}"
        );
    }
}

/// The resets of the world, whose withdrawals fail.
struct Unwithdrawable(std::sync::Arc<domain::auth::testing::InMemoryPasswordResets>);

#[async_trait::async_trait]
impl PasswordResets for Unwithdrawable {
    async fn issue(
        &self,
        member: domain::UserId,
        by: domain::UserId,
        now: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) -> Result<ResetToken, AuthError> {
        self.0.issue(member, by, now, expires_at).await
    }

    async fn request(
        &self,
        member: domain::UserId,
        now: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) -> Result<Option<ResetToken>, AuthError> {
        self.0.request(member, now, expires_at).await
    }

    async fn withdraw(&self, _: &ResetToken, _: OffsetDateTime) -> Result<(), AuthError> {
        Err(anyhow::anyhow!("the database is down").into())
    }

    async fn find_open(
        &self,
        token: &ResetToken,
        now: OffsetDateTime,
    ) -> Result<Option<OpenReset>, AuthError> {
        self.0.find_open(token, now).await
    }

    async fn reset(
        &self,
        token: &ResetToken,
        hash: &domain::auth::PasswordHash,
        now: OffsetDateTime,
    ) -> Result<domain::auth::PasswordChange, AuthError> {
        self.0.reset(token, hash, now).await
    }

    async fn delete_ended(&self, before: OffsetDateTime) -> Result<usize, AuthError> {
        self.0.delete_ended(before).await
    }
}

#[tokio::test]
async fn a_withdrawal_that_fails_leaves_the_mails_failure_to_report() {
    let w = world().await;
    w.mailer.break_down();
    let request = RequestPasswordReset::new(
        Registrations::Open,
        w.origin.clone(),
        w.intro.clone(),
        w.accounts.clone(),
        std::sync::Arc::new(Unwithdrawable(w.resets.clone())),
        w.mailer.clone(),
    );

    let asked = request
        .execute(&Email::parse("alice@idp.test").unwrap(), now())
        .await;

    let told = format!("{asked:?}");
    assert!(told.contains("the mail server is down"), "{told}");
    assert!(!told.contains("the database is down"), "{told}");
}

/// A budget of reset mails spent.
struct Spent;

#[async_trait::async_trait]
impl ResetMailer for Spent {
    async fn send_reset_link(&self, _: &ResetMail) -> Result<(), AuthError> {
        Err(AuthError::MailBudgetSpent)
    }
}

#[tokio::test]
async fn while_the_mail_budget_is_spent_an_accounts_open_link_keeps_working() {
    let w = world().await;
    let admin = w.an_admin().await;
    let admins = w
        .resets
        .issue(w.alice.id, admin.id, now(), now() + RESET_TTL)
        .await
        .unwrap();
    let spent = RequestPasswordReset::new(
        Registrations::Open,
        w.origin.clone(),
        w.intro.clone(),
        w.accounts.clone(),
        w.resets.clone(),
        std::sync::Arc::new(Spent),
    );

    let later = now() + Duration::minutes(1);
    let asked = spent
        .execute(&Email::parse("alice@idp.test").unwrap(), later)
        .await;

    assert!(
        matches!(asked, Err(AuthError::MailBudgetSpent)),
        "{asked:?}"
    );
    assert!(
        w.resets.find_open(&admins, later).await.unwrap().is_some(),
        "the admin's link still works"
    );
    ask(&w, "alice@idp.test").await.unwrap();
    let mailed = token_of(&w.mailer.reset_mails()[0]);
    spent
        .execute(&Email::parse("alice@idp.test").unwrap(), later)
        .await
        .unwrap_err();
    assert!(
        w.resets.find_open(&mailed, later).await.unwrap().is_some(),
        "and so does a mailed one"
    );
}
