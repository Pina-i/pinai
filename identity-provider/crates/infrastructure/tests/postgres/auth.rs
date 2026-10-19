use std::sync::Arc;

use domain::UserId;
use domain::auth::SignUps;
use domain::auth::testing::{SignInSeeds, a_request, contract};
use domain::auth::{LoginTickets, SignInAccount, SignupCodes};
use hmac::{Hmac, Mac};
use infrastructure::postgres::{
    PgAuthorizationCodes, PgClientSignIns, PgLoginTickets, PgSecondFactors, PgSignInAccounts,
    PgSignUps, PgSignupCodes,
};
use sha2::Sha256;
use sqlx::PgPool;
use time::{Duration, OffsetDateTime};

use super::a_user;

struct PgSignInSeeds(PgPool);

#[async_trait::async_trait]
impl SignInSeeds for PgSignInSeeds {
    async fn sign_up(&self, account: &SignInAccount) {
        sqlx::query(
            "INSERT INTO users (id, username, email, password_hash, display_name, \
                                email_verified_at, totp_enabled) \
             VALUES ($1, $2, $3, $4, $5, CASE WHEN $6 THEN now() END, $7)",
        )
        .bind(account.id.as_uuid())
        .bind(&account.username)
        .bind(&account.email)
        .bind(account.password_hash.as_str())
        .bind(&account.display_name)
        .bind(account.email_verified)
        .bind(account.totp_enabled)
        .execute(&self.0)
        .await
        .expect("seed an account");
    }
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn an_account_is_found_by_email_and_id_with_its_sign_in_state(pool: PgPool) {
    contract::an_account_is_found_by_email_and_id_with_its_sign_in_state(
        &PgSignInAccounts::new(pool.clone()),
        &PgSignInSeeds(pool),
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_code_is_good_once_and_only_until_it_expires(pool: PgPool) {
    let user = a_user(&pool).await;
    contract::a_code_is_good_once_and_only_until_it_expires(&PgAuthorizationCodes::new(pool), user)
        .await;
}

fn later() -> OffsetDateTime {
    OffsetDateTime::now_utc() + Duration::minutes(5)
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_login_ticket_keeps_the_request_and_closes_the_accounts_earlier_one(pool: PgPool) {
    let user = a_user(&pool).await;
    let tickets = PgLoginTickets::new(pool.clone());
    let request = a_request();

    let earlier = tickets.open(user, &request, later()).await.unwrap();
    let latest = tickets.open(user, &request, later()).await.unwrap();

    let open: Vec<(uuid::Uuid, String, String, String, String, Option<String>)> = sqlx::query_as(
        "SELECT id, client_id, redirect_uri, oauth_state, code_challenge, nonce \
         FROM pending_totp_logins WHERE consumed_at IS NULL",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_ne!(earlier, latest);
    assert_eq!(
        open,
        vec![(
            latest.as_uuid(),
            request.client.as_str().to_owned(),
            request.redirect_uri.clone(),
            request.state.clone(),
            request.challenge.as_str().to_owned(),
            request.nonce.clone(),
        )]
    );
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_signup_code_is_kept_only_as_its_hmac_and_retires_the_earlier_one(pool: PgPool) {
    let user: UserId = a_user(&pool).await;
    let pepper = b"the-pepper".to_vec();
    let codes = PgSignupCodes::new(pool.clone(), Arc::new(pepper.clone()));

    codes.issue(user, later()).await.unwrap();
    let latest = codes.issue(user, later()).await.unwrap();

    let open: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT code_hash FROM email_verification_codes WHERE consumed_at IS NULL",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    let mut mac = Hmac::<Sha256>::new_from_slice(&pepper).unwrap();
    mac.update(latest.as_str().as_bytes());
    assert_eq!(open, vec![mac.finalize().into_bytes().to_vec()]);
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_new_account_is_unconfirmed_and_found_by_its_email(pool: PgPool) {
    contract::a_new_account_is_unconfirmed_and_found_by_its_email(
        &PgSignUps::new(pool.clone()),
        &PgSignInAccounts::new(pool),
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn accounts_left_unconfirmed_are_deleted_after_their_grace(pool: PgPool) {
    contract::accounts_left_unconfirmed_are_deleted_after_their_grace(
        &PgSignUps::new(pool.clone()),
        &PgSignInAccounts::new(pool.clone()),
        &PgSignInSeeds(pool),
    )
    .await;
}

/// Codes over an account still to confirm.
async fn codes_for_bob(pool: &PgPool) -> (PgSignupCodes, UserId) {
    let bob = contract::a_new_account("bob");
    PgSignUps::new(pool.clone()).create(&bob).await.unwrap();
    (
        PgSignupCodes::new(pool.clone(), Arc::new(b"the-pepper".to_vec())),
        bob.id,
    )
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_signup_code_confirms_its_account_once(pool: PgPool) {
    let (codes, bob) = codes_for_bob(&pool).await;
    contract::a_signup_code_confirms_its_account_once(&codes, &PgSignInAccounts::new(pool), bob)
        .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn wrong_codes_count_down_to_exhaustion(pool: PgPool) {
    let (codes, bob) = codes_for_bob(&pool).await;
    contract::wrong_codes_count_down_to_exhaustion(&codes, bob).await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn only_the_latest_live_code_counts(pool: PgPool) {
    let (codes, bob) = codes_for_bob(&pool).await;
    contract::only_the_latest_live_code_counts(&codes, bob).await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn the_codes_issued_lately_are_counted(pool: PgPool) {
    let (codes, bob) = codes_for_bob(&pool).await;
    contract::the_codes_issued_lately_are_counted(&codes, bob).await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn spent_codes_are_deleted_and_the_live_one_kept(pool: PgPool) {
    let (codes, bob) = codes_for_bob(&pool).await;
    contract::spent_codes_are_deleted_and_the_live_one_kept(&codes, bob).await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn spent_login_tickets_are_deleted_and_the_open_one_kept(pool: PgPool) {
    let user = a_user(&pool).await;
    let tickets = PgLoginTickets::new(pool.clone());
    let now = OffsetDateTime::now_utc();
    tickets.open(user, &a_request(), later()).await.unwrap();
    let open = tickets.open(user, &a_request(), later()).await.unwrap();

    let deleted = tickets
        .delete_spent(now, now + Duration::minutes(1))
        .await
        .unwrap();

    let left: Vec<uuid::Uuid> = sqlx::query_scalar("SELECT id FROM pending_totp_logins")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!((deleted, left), (1, vec![open.as_uuid()]));
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn parallel_wrong_guesses_never_pass_the_cap(pool: PgPool) {
    let (codes, bob) = codes_for_bob(&pool).await;
    let codes = Arc::new(codes);
    let now = OffsetDateTime::now_utc();
    let code = codes
        .issue(bob, now + domain::auth::SIGNUP_CODE_TTL)
        .await
        .unwrap();
    let wrong = domain::auth::OtpCode::parse(if code.as_str() == "000000" {
        "111111"
    } else {
        "000000"
    })
    .unwrap();

    let guesses: Vec<_> = (0..20)
        .map(|_| {
            let (codes, wrong) = (codes.clone(), wrong.clone());
            tokio::spawn(async move { codes.attempt(bob, &wrong, now).await.unwrap() })
        })
        .collect();
    let mut wrong_answers = 0;
    for guess in guesses {
        if matches!(
            guess.await.unwrap(),
            domain::auth::CodeAttempt::Wrong { .. }
        ) {
            wrong_answers += 1;
        }
    }

    let attempts: i32 = sqlx::query_scalar(
        "SELECT attempts FROM email_verification_codes WHERE consumed_at IS NULL",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!((wrong_answers, attempts), (5, 5));
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn an_address_or_a_handle_is_one_accounts_whatever_its_case(pool: PgPool) {
    contract::an_address_or_a_handle_is_one_accounts_whatever_its_case(
        &PgSignUps::new(pool.clone()),
        &PgSignInAccounts::new(pool.clone()),
        &PgSignInSeeds(pool),
    )
    .await;
}

fn factors(pool: &PgPool) -> PgSecondFactors {
    PgSecondFactors::new(pool.clone(), Arc::new(b"the-pepper".to_vec()))
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn an_enrollment_waits_until_the_second_factor_is_turned_on(pool: PgPool) {
    let user = a_user(&pool).await;
    contract::an_enrollment_waits_until_the_second_factor_is_turned_on(&factors(&pool), user).await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn turning_the_second_factor_on_mints_its_codes_and_off_forgets_everything(pool: PgPool) {
    let user = a_user(&pool).await;
    contract::turning_the_second_factor_on_mints_its_codes_and_off_forgets_everything(
        &factors(&pool),
        &PgSignInAccounts::new(pool.clone()),
        user,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_recovery_code_is_used_once_and_a_new_set_replaces_the_old(pool: PgPool) {
    let user = a_user(&pool).await;
    contract::a_recovery_code_is_used_once_and_a_new_set_replaces_the_old(&factors(&pool), user)
        .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn an_app_signed_in_to_is_remembered_and_staying_signed_in_kept(pool: PgPool) {
    let (user, other) = (a_user(&pool).await, a_user(&pool).await);
    contract::an_app_signed_in_to_is_remembered_and_staying_signed_in_kept(
        &PgClientSignIns::new(pool),
        user,
        other,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn an_open_ticket_is_found_until_spent_or_expired(pool: PgPool) {
    let user = a_user(&pool).await;
    contract::an_open_ticket_is_found_until_spent_or_expired(&PgLoginTickets::new(pool), user)
        .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_time_step_is_used_once_and_only_forward(pool: PgPool) {
    let user = a_user(&pool).await;
    contract::a_time_step_is_used_once_and_only_forward(&factors(&pool), user).await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_ticket_gives_five_attempts_until_spent_or_expired(pool: PgPool) {
    let user = a_user(&pool).await;
    contract::a_ticket_gives_five_attempts_until_spent_or_expired(&PgLoginTickets::new(pool), user)
        .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn parallel_attempts_on_a_ticket_never_pass_its_five(pool: PgPool) {
    let user = a_user(&pool).await;
    let tickets = Arc::new(PgLoginTickets::new(pool));
    let now = OffsetDateTime::now_utc();
    let ticket = tickets.open(user, &a_request(), later()).await.unwrap();

    let attempts: Vec<_> = (0..20)
        .map(|_| {
            let tickets = tickets.clone();
            tokio::spawn(async move { tickets.reserve_attempt(ticket, now).await.unwrap() })
        })
        .collect();
    let mut open = 0;
    for attempt in attempts {
        if matches!(attempt.await.unwrap(), domain::auth::TicketAttempt::Open(_)) {
            open += 1;
        }
    }

    assert_eq!(open, 5);
}
