use domain::auth::REQUESTED_RESET_TTL;
use domain::auth::testing::RecordingMailer;

use super::*;

fn mail(to: &str) -> ResetMail {
    ResetMail {
        to: to.to_owned(),
        name: "alice".to_owned(),
        instance: "Aotearoa".to_owned(),
        link: "http://localhost:8080/r/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
        valid_for: REQUESTED_RESET_TTL,
    }
}

#[tokio::test]
async fn past_its_budget_a_link_is_refused_and_the_relay_never_asked() {
    let relay = Arc::new(RecordingMailer::default());
    let budget = ResetMailBudget::with(relay.clone(), 3, Duration::from_secs(3600));

    let mut sent = Vec::new();
    for n in 0..5 {
        sent.push(
            budget
                .send_reset_link(&mail(&format!("user{n}@idp.test")))
                .await,
        );
    }

    assert!(sent[..3].iter().all(Result::is_ok), "{sent:?}");
    for refused in &sent[3..] {
        assert!(
            matches!(refused, Err(AuthError::MailBudgetSpent)),
            "{refused:?}"
        );
    }
    assert_eq!(relay.reset_mails().len(), 3);
}

#[test]
fn the_budget_comes_back_one_mail_per_period_up_to_its_burst() {
    let start = Instant::now();
    let mut budget = Budget::full(2, Duration::from_secs(6), start);

    let spent = [
        budget.spend(start),
        budget.spend(start),
        budget.spend(start),
    ];
    let after_five_seconds = budget.spend(start + Duration::from_secs(5));
    let after_six = budget.spend(start + Duration::from_secs(6));
    let much_later = start + Duration::from_secs(3600);
    let then = [
        budget.spend(much_later),
        budget.spend(much_later),
        budget.spend(much_later),
    ];

    assert_eq!(spent, [true, true, false]);
    assert!(!after_five_seconds);
    assert!(after_six);
    assert_eq!(then, [true, true, false], "never more than the burst");
}

#[test]
fn the_instance_mails_sixty_then_one_every_six_seconds() {
    assert_eq!(ResetMailBudget::BURST, 60);
    assert_eq!(ResetMailBudget::EVERY, Duration::from_secs(6));
}
