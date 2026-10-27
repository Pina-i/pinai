use std::sync::Arc;

use domain::auth::testing::{
    PlainHasher, SignInSeeds, SignUpRecords, a_request, contract, seeded_actor, signed_up,
};
use domain::auth::{
    AuthorizationCodes, INVITATION_TTL, Invitations, LoginTickets, PasswordChange, PasswordResets,
    REQUESTED_RESET_TTL, RESET_REQUEST_LIMIT, RESET_TTL, RefreshTokens, Registration, Rotation,
    SessionKind, Sessions, SignInAccount, SignInAccounts, SignUps, SignupCodes,
};
use domain::{DeviceId, SessionId, UserId};
use hmac::{Hmac, Mac};
use infrastructure::postgres::{
    PgAuthorizationCodes, PgClientSignIns, PgInstanceMembers, PgInvitations, PgLoginTickets,
    PgPasswordResets, PgRefreshTokens, PgSecondFactors, PgSessions, PgSignInAccounts, PgSignUps,
    PgSignupCodes,
};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use time::{Duration, OffsetDateTime};

use super::a_user;

struct PgSignInSeeds(PgPool);

#[async_trait::async_trait]
impl SignInSeeds for PgSignInSeeds {
    async fn sign_up(&self, account: &SignInAccount) {
        sqlx::query(
            "INSERT INTO users (id, username, email, password_hash, display_name, \
                                email_verified_at, admitted_at, is_admin, totp_enabled, actor_uri) \
             VALUES ($1, $2, $3, $4, $5, CASE WHEN $6 THEN now() END, \
                     CASE WHEN $7 THEN now() END, $8, $9, $10)",
        )
        .bind(account.id.as_uuid())
        .bind(&account.username)
        .bind(&account.email)
        .bind(account.password_hash.as_str())
        .bind(&account.display_name)
        .bind(account.email_verified)
        .bind(account.admitted)
        .bind(account.admin)
        .bind(account.totp_enabled)
        .bind(seeded_actor(account).as_str())
        .execute(&self.0)
        .await
        .expect("seed an account");
    }
}

#[async_trait::async_trait]
impl SignUpRecords for PgSignInSeeds {
    async fn invited_by(&self, user: UserId) -> Option<UserId> {
        sqlx::query_scalar::<_, Option<uuid::Uuid>>("SELECT invited_by FROM users WHERE id = $1")
            .bind(user.as_uuid())
            .fetch_optional(&self.0)
            .await
            .expect("read who vouched for an account")
            .flatten()
            .map(UserId::from)
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
    let session = PgSessions::new(pool.clone())
        .open(user, &SessionKind::Browser, OffsetDateTime::now_utc())
        .await
        .unwrap();
    contract::a_code_is_good_once_and_only_until_it_expires(
        &PgAuthorizationCodes::new(pool),
        user,
        session,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_session_opens_is_used_and_ends_once(pool: PgPool) {
    let user = a_user(&pool).await;
    contract::a_session_opens_is_used_and_ends_once(&PgSessions::new(pool), user).await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn sessions_ended_are_swept_after_their_retention(pool: PgPool) {
    let user = a_user(&pool).await;
    contract::sessions_ended_are_swept_after_their_retention(&PgSessions::new(pool), user).await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_session_goes_with_its_account_and_its_codes_with_it(pool: PgPool) {
    let user = a_user(&pool).await;
    let sessions = PgSessions::new(pool.clone());
    let session = sessions
        .open(user, &SessionKind::Browser, OffsetDateTime::now_utc())
        .await
        .unwrap();
    let code = PgAuthorizationCodes::new(pool.clone())
        .issue(
            &domain::auth::Grant::answering(user, session, &a_request()),
            later(),
        )
        .await
        .unwrap();

    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user.as_uuid())
        .execute(&pool)
        .await
        .unwrap();

    assert_eq!(sessions.find(session).await.unwrap(), None);
    assert_eq!(
        PgAuthorizationCodes::new(pool)
            .consume(&code, OffsetDateTime::now_utc())
            .await
            .unwrap(),
        None
    );
}

fn later() -> OffsetDateTime {
    OffsetDateTime::now_utc() + Duration::minutes(5)
}

async fn a_device_of(pool: &PgPool, user: UserId) -> DeviceId {
    let device = DeviceId::generate();
    sqlx::query(
        "INSERT INTO user_devices (device_id, user_id, display_name, kind) \
         VALUES ($1, $2, 'Firefox on Linux', 'laptop')",
    )
    .bind(device.as_uuid())
    .bind(user.as_uuid())
    .execute(pool)
    .await
    .expect("seed a device");
    device
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_device_holds_one_session_the_latest_linked(pool: PgPool) {
    let user = a_user(&pool).await;
    let device = a_device_of(&pool, user).await;
    contract::a_device_holds_one_session_the_latest_linked(&PgSessions::new(pool), user, device)
        .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_revoked_device_and_signing_out_elsewhere_end_the_right_sessions(pool: PgPool) {
    let (user, other) = (a_user(&pool).await, a_user(&pool).await);
    let device = a_device_of(&pool, user).await;
    contract::a_revoked_device_and_signing_out_elsewhere_end_the_right_sessions(
        &PgSessions::new(pool),
        user,
        other,
        device,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_session_forgets_a_device_deleted_with_its_rows(pool: PgPool) {
    let user = a_user(&pool).await;
    let device = a_device_of(&pool, user).await;
    let sessions = PgSessions::new(pool.clone());
    let session = sessions
        .open(user, &SessionKind::Browser, OffsetDateTime::now_utc())
        .await
        .unwrap();
    sessions
        .link(session, device, OffsetDateTime::now_utc())
        .await
        .unwrap();

    sqlx::query("DELETE FROM user_devices WHERE device_id = $1")
        .bind(device.as_uuid())
        .execute(&pool)
        .await
        .unwrap();

    assert_eq!(sessions.find(session).await.unwrap().unwrap().device, None);
}

async fn a_session(pool: &PgPool) -> SessionId {
    let user = a_user(pool).await;
    PgSessions::new(pool.clone())
        .open(user, &SessionKind::Browser, OffsetDateTime::now_utc())
        .await
        .unwrap()
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_refresh_token_rotates_at_each_use_and_a_used_one_is_reused(pool: PgPool) {
    let session = a_session(&pool).await;
    contract::a_refresh_token_rotates_at_each_use_and_a_used_one_is_reused(
        &PgRefreshTokens::new(pool),
        session,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_lost_answer_is_answered_again_within_the_grace(pool: PgPool) {
    let session = a_session(&pool).await;
    contract::a_lost_answer_is_answered_again_within_the_grace(
        &PgRefreshTokens::new(pool),
        session,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_refresh_token_names_its_session_to_its_own_client_only(pool: PgPool) {
    let session = a_session(&pool).await;
    contract::a_refresh_token_names_its_session_to_its_own_client_only(
        &PgRefreshTokens::new(pool),
        session,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn refresh_tokens_unused_since_the_cutoff_are_swept(pool: PgPool) {
    let session = a_session(&pool).await;
    contract::refresh_tokens_unused_since_the_cutoff_are_swept(
        &PgRefreshTokens::new(pool),
        session,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn parallel_presentations_of_one_token_leave_its_chain_one_head(pool: PgPool) {
    let session = a_session(&pool).await;
    let tokens = Arc::new(PgRefreshTokens::new(pool));
    let client = a_request().client;
    let now = OffsetDateTime::now_utc();
    let first = tokens.start(session, &client, now).await.unwrap();

    let presentations: Vec<_> = (0..8)
        .map(|_| {
            let (tokens, first, client) = (tokens.clone(), first.clone(), client.clone());
            tokio::spawn(async move { tokens.rotate(&first, &client, now).await.unwrap() })
        })
        .collect();
    let mut successors = Vec::new();
    for presentation in presentations {
        match presentation.await.unwrap() {
            Rotation::Rotated { successor, .. } => successors.push(successor),
            other => panic!("within the grace, each is answered: {other:?}"),
        }
    }
    let mut heads = 0;
    for successor in &successors {
        let rotation = tokens
            .rotate(successor, &client, now + Duration::seconds(1))
            .await
            .unwrap();
        if matches!(rotation, Rotation::Rotated { .. }) {
            heads += 1;
        }
    }

    successors.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    successors.dedup();
    assert_eq!(successors.len(), 8);
    assert_eq!(heads, 1, "each answer replaced the one before");
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_refresh_token_is_kept_as_its_hash_and_goes_with_its_session(pool: PgPool) {
    let user = a_user(&pool).await;
    let now = OffsetDateTime::now_utc();
    let session = PgSessions::new(pool.clone())
        .open(user, &SessionKind::App(a_request().client), now)
        .await
        .unwrap();
    let token = PgRefreshTokens::new(pool.clone())
        .start(session, &a_request().client, now)
        .await
        .unwrap();

    let kept: Vec<Vec<u8>> = sqlx::query_scalar("SELECT token_hash FROM refresh_tokens")
        .fetch_all(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user.as_uuid())
        .execute(&pool)
        .await
        .unwrap();
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM refresh_tokens")
        .fetch_one(&pool)
        .await
        .unwrap();

    assert_eq!(token.as_str().len(), 43, "256 bits, base64url");
    assert_eq!(
        kept,
        vec![Sha256::digest(token.as_str().as_bytes()).to_vec()]
    );
    assert_eq!(left, 0);
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

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn an_admitted_account_is_never_swept_as_unconfirmed(pool: PgPool) {
    contract::an_admitted_account_is_never_swept_as_unconfirmed(
        &PgSignUps::new(pool.clone()),
        &PgSignInAccounts::new(pool.clone()),
        &PgSignInSeeds(pool),
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn the_admin_is_created_admitted_unconfirmed_and_never_written_over(pool: PgPool) {
    contract::the_admin_is_created_admitted_unconfirmed_and_never_written_over(
        &PgSignUps::new(pool.clone()),
        &PgSignInAccounts::new(pool.clone()),
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn the_admin_facts_tell_who_has_an_address_and_whether_any_admin_exists(pool: PgPool) {
    contract::the_admin_facts_tell_who_has_an_address_and_whether_any_admin_exists(
        &PgSignUps::new(pool.clone()),
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

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn an_invited_account_is_created_admitted_vouched_for_and_spends_its_invitation(
    pool: PgPool,
) {
    contract::an_invited_account_is_created_admitted_vouched_for_and_spends_its_invitation(
        &PgSignUps::new(pool.clone()),
        &PgInvitations::new(pool.clone()),
        &PgSignInAccounts::new(pool.clone()),
        &PgSignInSeeds(pool),
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_revoked_expired_or_unknown_invitation_lets_nobody_in(pool: PgPool) {
    contract::a_revoked_expired_or_unknown_invitation_lets_nobody_in(
        &PgSignUps::new(pool.clone()),
        &PgInvitations::new(pool.clone()),
        &PgSignInAccounts::new(pool),
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn an_address_already_taken_leaves_the_invitation_open(pool: PgPool) {
    contract::an_address_already_taken_leaves_the_invitation_open(
        &PgSignUps::new(pool.clone()),
        &PgInvitations::new(pool.clone()),
        &PgSignInSeeds(pool),
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn the_open_invitations_are_listed_newest_first(pool: PgPool) {
    contract::the_open_invitations_are_listed_newest_first(
        &PgSignUps::new(pool.clone()),
        &PgInvitations::new(pool),
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn invitations_are_swept_a_while_after_they_ended(pool: PgPool) {
    contract::invitations_are_swept_a_while_after_they_ended(
        &PgSignUps::new(pool.clone()),
        &PgInvitations::new(pool),
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn sign_ups_racing_for_one_invitation_create_one_account(pool: PgPool) {
    let now = OffsetDateTime::now_utc();
    let sign_ups = Arc::new(PgSignUps::new(pool.clone()));
    let admin = contract::a_new_account("admin");
    sign_ups.create_admin(&admin, now).await.unwrap();
    let (invitation, _) = PgInvitations::new(pool.clone())
        .issue(admin.id, now, now + INVITATION_TTL)
        .await
        .unwrap();

    let racers: Vec<_> = (0..8)
        .map(|n| {
            let sign_ups = sign_ups.clone();
            let account = contract::a_new_account(&format!("racer{n}"));
            tokio::spawn(async move {
                sign_ups
                    .create_invited(&account, invitation, now)
                    .await
                    .unwrap()
            })
        })
        .collect();
    let mut answers = Vec::new();
    for racer in racers {
        answers.push(racer.await.unwrap());
    }

    let created = answers
        .iter()
        .filter(|answer| **answer == Registration::Created)
        .count();
    let spent = answers
        .iter()
        .filter(|answer| **answer == Registration::InvitationSpent)
        .count();
    let invited: i64 = sqlx::query_scalar("SELECT count(*) FROM users WHERE invited_by = $1")
        .bind(admin.id.as_uuid())
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!((created, spent, invited), (1, 7, 1), "{answers:?}");
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn an_invitation_token_is_kept_as_its_hash_and_goes_with_its_creator(pool: PgPool) {
    let now = OffsetDateTime::now_utc();
    let admin = contract::a_new_account("admin");
    PgSignUps::new(pool.clone())
        .create_admin(&admin, now)
        .await
        .unwrap();
    let (_, token) = PgInvitations::new(pool.clone())
        .issue(admin.id, now, now + INVITATION_TTL)
        .await
        .unwrap();

    let kept: Vec<Vec<u8>> = sqlx::query_scalar("SELECT token_hash FROM invitations")
        .fetch_all(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(admin.id.as_uuid())
        .execute(&pool)
        .await
        .unwrap();
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM invitations")
        .fetch_one(&pool)
        .await
        .unwrap();

    assert_eq!(token.as_str().len(), 43, "256 bits, base64url");
    assert_eq!(
        kept,
        vec![Sha256::digest(token.as_str().as_bytes()).to_vec()]
    );
    assert_eq!(left, 0);
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn issuing_a_link_replaces_the_members_open_one(pool: PgPool) {
    contract::issuing_a_link_replaces_the_members_open_one(
        &PgPasswordResets::new(pool.clone()),
        &PgSignUps::new(pool.clone()),
        &PgSignInSeeds(pool),
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_reset_sets_the_password_spends_the_link_and_ends_what_the_old_password_opened(
    pool: PgPool,
) {
    contract::a_reset_sets_the_password_spends_the_link_and_ends_what_the_old_password_opened(
        &PgPasswordResets::new(pool.clone()),
        &PgSignInAccounts::new(pool.clone()),
        &PgSessions::new(pool.clone()),
        &PgLoginTickets::new(pool.clone()),
        &PgSignUps::new(pool.clone()),
        &PgSignInSeeds(pool),
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_replaced_expired_or_unknown_link_resets_nothing(pool: PgPool) {
    contract::a_replaced_expired_or_unknown_link_resets_nothing(
        &PgPasswordResets::new(pool.clone()),
        &PgSignInAccounts::new(pool.clone()),
        &PgSessions::new(pool.clone()),
        &PgSignUps::new(pool.clone()),
        &PgSignInSeeds(pool),
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn reset_links_are_swept_a_while_after_they_ended(pool: PgPool) {
    contract::reset_links_are_swept_a_while_after_they_ended(
        &PgPasswordResets::new(pool.clone()),
        &PgSignUps::new(pool.clone()),
        &PgSignInSeeds(pool),
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_link_through_the_mailbox_has_no_maker_and_replaces_the_open_one_an_admins_too(
    pool: PgPool,
) {
    contract::a_link_through_the_mailbox_has_no_maker_and_replaces_the_open_one_an_admins_too(
        &PgPasswordResets::new(pool.clone()),
        &PgSignUps::new(pool.clone()),
        &PgSignInSeeds(pool),
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn five_links_asked_for_an_hour_and_the_next_makes_nothing(pool: PgPool) {
    contract::five_links_asked_for_an_hour_and_the_next_makes_nothing(
        &PgPasswordResets::new(pool.clone()),
        &PgSignUps::new(pool.clone()),
        &PgSignInSeeds(pool),
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_link_withdrawn_neither_counts_nor_works(pool: PgPool) {
    contract::a_link_withdrawn_neither_counts_nor_works(
        &PgPasswordResets::new(pool.clone()),
        &PgSignInSeeds(pool),
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn withdrawing_a_link_gives_back_the_open_one_it_replaced_an_admins_included(pool: PgPool) {
    contract::withdrawing_a_link_gives_back_the_open_one_it_replaced_an_admins_included(
        &PgPasswordResets::new(pool.clone()),
        &PgSignUps::new(pool.clone()),
        &PgSignInSeeds(pool),
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_replaced_link_expired_or_replaced_again_is_not_given_back(pool: PgPool) {
    contract::a_replaced_link_expired_or_replaced_again_is_not_given_back(
        &PgPasswordResets::new(pool.clone()),
        &PgSignUps::new(pool.clone()),
        &PgSignInSeeds(pool),
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_link_used_or_an_admins_is_never_withdrawn(pool: PgPool) {
    contract::a_link_used_or_an_admins_is_never_withdrawn(
        &PgPasswordResets::new(pool.clone()),
        &PgSignUps::new(pool.clone()),
        &PgSignInSeeds(pool),
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn the_members_are_listed_most_recently_active_first(pool: PgPool) {
    contract::the_members_are_listed_most_recently_active_first(
        &PgInstanceMembers::new(pool.clone()),
        &PgSessions::new(pool.clone()),
        &PgSignUps::new(pool.clone()),
        &PgSignInSeeds(pool),
    )
    .await;
}

/// The instance's admin and a member, `alice`.
async fn an_admin_and_alice(pool: &PgPool) -> (UserId, SignInAccount) {
    let admin = contract::a_new_account("admin");
    PgSignUps::new(pool.clone())
        .create_admin(&admin, OffsetDateTime::now_utc())
        .await
        .unwrap();
    let alice = signed_up("alice");
    PgSignInSeeds(pool.clone()).sign_up(&alice).await;
    (admin.id, alice)
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn two_submissions_racing_on_one_link_change_the_password_once(pool: PgPool) {
    let (admin, alice) = an_admin_and_alice(&pool).await;
    let now = OffsetDateTime::now_utc();
    let sessions = PgSessions::new(pool.clone());
    for _ in 0..3 {
        sessions
            .open(alice.id, &SessionKind::Browser, now)
            .await
            .unwrap();
    }
    let resets = Arc::new(PgPasswordResets::new(pool.clone()));
    let token = resets
        .issue(alice.id, admin, now, now + RESET_TTL)
        .await
        .unwrap();

    let racers: Vec<_> = (0..8)
        .map(|n| {
            let (resets, token) = (resets.clone(), token.clone());
            tokio::spawn(async move {
                let hash = PlainHasher::hash(&format!("racer-{n}-password"));
                let outcome = resets.reset(&token, &hash, now).await.unwrap();
                (hash, outcome)
            })
        })
        .collect();
    let mut changed = Vec::new();
    for racer in racers {
        if let (hash, PasswordChange::Changed { ended, .. }) = racer.await.unwrap() {
            changed.push((hash, ended.len()));
        }
    }

    assert_eq!(changed.len(), 1, "one submission changes the password");
    let (winner, ended) = &changed[0];
    assert_eq!(*ended, 3);
    assert_eq!(
        &PgSignInAccounts::new(pool.clone())
            .by_id(alice.id)
            .await
            .unwrap()
            .unwrap()
            .password_hash,
        winner
    );
    let reset: i64 =
        sqlx::query_scalar("SELECT count(*) FROM sessions WHERE revoked_reason = 'password_reset'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(reset, 3, "each session ended once, as password_reset");
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn links_issued_at_once_for_one_member_leave_one_open(pool: PgPool) {
    let (admin, alice) = an_admin_and_alice(&pool).await;
    let now = OffsetDateTime::now_utc();
    let resets = Arc::new(PgPasswordResets::new(pool.clone()));

    let issuers: Vec<_> = (0..8)
        .map(|_| {
            let resets = resets.clone();
            tokio::spawn(async move { resets.issue(alice.id, admin, now, now + RESET_TTL).await })
        })
        .collect();
    let mut tokens = Vec::new();
    for issuer in issuers {
        tokens.push(issuer.await.unwrap().expect("each issued"));
    }

    let mut open = 0;
    for token in &tokens {
        if resets.find_open(token, now).await.unwrap().is_some() {
            open += 1;
        }
    }
    assert_eq!(open, 1, "each replaced the one before");
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn the_store_holds_one_link_per_account_neither_used_nor_replaced(pool: PgPool) {
    let (admin, alice) = an_admin_and_alice(&pool).await;
    let now = OffsetDateTime::now_utc();
    PgPasswordResets::new(pool.clone())
        .issue(alice.id, admin, now, now + RESET_TTL)
        .await
        .unwrap();

    let another = sqlx::query(
        "INSERT INTO password_resets (token_hash, user_id, created_by, created_at, expires_at) \
         VALUES ($1, $2, $3, now(), now() + interval '1 day')",
    )
    .bind(vec![7u8; 32])
    .bind(alice.id.as_uuid())
    .bind(admin.as_uuid())
    .execute(&pool)
    .await;

    let Err(sqlx::Error::Database(refused)) = another else {
        panic!("a second open link was kept: {another:?}");
    };
    assert_eq!(refused.constraint(), Some("password_resets_one_open"));
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_reset_token_is_kept_as_its_hash_and_goes_with_its_member(pool: PgPool) {
    let (admin, alice) = an_admin_and_alice(&pool).await;
    let now = OffsetDateTime::now_utc();
    let token = PgPasswordResets::new(pool.clone())
        .issue(alice.id, admin, now, now + RESET_TTL)
        .await
        .unwrap();

    let kept: Vec<Vec<u8>> = sqlx::query_scalar("SELECT token_hash FROM password_resets")
        .fetch_all(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(alice.id.as_uuid())
        .execute(&pool)
        .await
        .unwrap();
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM password_resets")
        .fetch_one(&pool)
        .await
        .unwrap();

    assert_eq!(token.as_str().len(), 43, "256 bits, base64url");
    assert_eq!(
        kept,
        vec![Sha256::digest(token.as_str().as_bytes()).to_vec()]
    );
    assert_eq!(left, 0);
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_link_asked_for_by_mail_is_kept_with_no_maker_and_outlives_any_admin(pool: PgPool) {
    let (admin, alice) = an_admin_and_alice(&pool).await;
    let now = OffsetDateTime::now_utc();
    let resets = PgPasswordResets::new(pool.clone());
    let token = resets
        .request(alice.id, now, now + REQUESTED_RESET_TTL)
        .await
        .unwrap()
        .expect("within the limit");

    let makers: Vec<Option<uuid::Uuid>> =
        sqlx::query_scalar("SELECT created_by FROM password_resets")
            .fetch_all(&pool)
            .await
            .unwrap();
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(admin.as_uuid())
        .execute(&pool)
        .await
        .unwrap();

    assert_eq!(makers, vec![None]);
    assert!(
        resets.find_open(&token, now).await.unwrap().is_some(),
        "no admin's link to go with them"
    );
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn requests_at_once_for_one_account_never_pass_five_an_hour(pool: PgPool) {
    let (_, alice) = an_admin_and_alice(&pool).await;
    let now = OffsetDateTime::now_utc();
    let resets = Arc::new(PgPasswordResets::new(pool.clone()));

    let askers: Vec<_> = (0..12)
        .map(|_| {
            let resets = resets.clone();
            tokio::spawn(async move {
                resets
                    .request(alice.id, now, now + REQUESTED_RESET_TTL)
                    .await
                    .unwrap()
            })
        })
        .collect();
    let mut made = Vec::new();
    for asker in askers {
        made.extend(asker.await.unwrap());
    }

    assert_eq!(made.len(), RESET_REQUEST_LIMIT);
    let mut open = 0;
    for token in &made {
        if resets.find_open(token, now).await.unwrap().is_some() {
            open += 1;
        }
    }
    assert_eq!(open, 1, "each replaced the one before");
    let kept: i64 = sqlx::query_scalar("SELECT count(*) FROM password_resets")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(usize::try_from(kept).unwrap(), RESET_REQUEST_LIMIT);
}
