use std::sync::Arc;

use anyhow::Context;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use domain::auth::{
    AddressHolder, AdminFacts, AuthError, AuthorizationCode, AuthorizationCodes,
    AuthorizationRequest, CODE_ATTEMPTS, ClientId, ClientSignIn, ClientSignIns, CodeAttempt,
    CodeChallenge, Email, Grant, InstanceMember, InstanceMembers, Invitation, InvitationToken,
    Invitations, LoginTickets, NewAccount, OpenInvitation, OpenReset, OtpCode, PasswordChange,
    PasswordHash, PasswordReset, PasswordResets, Presentation, RESET_REQUEST_WINDOW, RefreshLink,
    RefreshToken, RefreshTokens, Registration, ResetToken, RevokedReason, Rotation, SESSION_IDLE,
    Session, SessionKind, Sessions, SignInAccount, SignInAccounts, SignUps, SignupCodes,
    may_request_reset,
};
use domain::auth::{
    RECOVERY_CODES, SecondFactors, TICKET_ATTEMPTS, Ticket, TicketAttempt, TotpSecret,
};
use domain::identity::ActorUri;
use domain::{DeviceId, InvitationId, SessionId, TicketId, UserId};
use hmac::{Hmac, Mac};
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use time::OffsetDateTime;

/// `authorization_codes`: `used` flips once, in the `UPDATE` that reads the grant back.
pub struct PgAuthorizationCodes {
    pool: PgPool,
}

impl PgAuthorizationCodes {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(sqlx::FromRow)]
struct GrantRow {
    user_id: uuid::Uuid,
    session_id: uuid::Uuid,
    client_id: String,
    redirect_uri: String,
    scope: String,
    code_challenge: String,
    code_challenge_method: String,
    nonce: Option<String>,
}

impl TryFrom<GrantRow> for Grant {
    type Error = anyhow::Error;

    fn try_from(row: GrantRow) -> Result<Self, Self::Error> {
        Ok(Grant {
            user: row.user_id.into(),
            session: row.session_id.into(),
            client: ClientId::parse(&row.client_id).context("authorization_codes.client_id")?,
            redirect_uri: row.redirect_uri,
            scope: row.scope,
            challenge: CodeChallenge::parse(&row.code_challenge, &row.code_challenge_method)
                .context("authorization_codes.code_challenge_method")?,
            nonce: row.nonce,
        })
    }
}

#[async_trait::async_trait]
impl AuthorizationCodes for PgAuthorizationCodes {
    async fn issue(
        &self,
        grant: &Grant,
        expires_at: OffsetDateTime,
    ) -> Result<AuthorizationCode, AuthError> {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let code = URL_SAFE_NO_PAD.encode(bytes);
        sqlx::query(
            "INSERT INTO authorization_codes \
                 (code, client_id, user_id, session_id, redirect_uri, code_challenge, \
                  code_challenge_method, scope, nonce, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, 'S256', $7, $8, $9)",
        )
        .bind(&code)
        .bind(grant.client.as_str())
        .bind(grant.user.as_uuid())
        .bind(grant.session.as_uuid())
        .bind(&grant.redirect_uri)
        .bind(grant.challenge.as_str())
        .bind(&grant.scope)
        .bind(&grant.nonce)
        .bind(expires_at)
        .execute(&self.pool)
        .await
        .context("issue an authorization code")?;
        Ok(AuthorizationCode::new(code))
    }

    async fn consume(
        &self,
        code: &AuthorizationCode,
        now: OffsetDateTime,
    ) -> Result<Option<Grant>, AuthError> {
        let row: Option<GrantRow> = sqlx::query_as(
            "UPDATE authorization_codes SET used = true \
             WHERE code = $1 AND used = false AND expires_at > $2 \
             RETURNING user_id, session_id, client_id, redirect_uri, scope, code_challenge, \
                       code_challenge_method, nonce",
        )
        .bind(code.as_str())
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .context("consume an authorization code")?;
        Ok(row.map(Grant::try_from).transpose()?)
    }
}

/// `users`, as signing in reads it.
pub struct PgSignInAccounts {
    pool: PgPool,
}

impl PgSignInAccounts {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

const SIGN_IN_COLUMNS: &str = "id, email, username, display_name, password_hash, \
     email_verified_at IS NOT NULL AS email_verified, admitted_at IS NOT NULL AS admitted, \
     is_admin, totp_enabled";

#[derive(sqlx::FromRow)]
struct SignInRow {
    id: uuid::Uuid,
    email: String,
    username: String,
    display_name: Option<String>,
    password_hash: String,
    email_verified: bool,
    admitted: bool,
    is_admin: bool,
    totp_enabled: bool,
}

impl From<SignInRow> for SignInAccount {
    fn from(row: SignInRow) -> Self {
        SignInAccount {
            id: row.id.into(),
            email: row.email,
            username: row.username,
            display_name: row.display_name,
            password_hash: PasswordHash::new(row.password_hash),
            email_verified: row.email_verified,
            admitted: row.admitted,
            admin: row.is_admin,
            totp_enabled: row.totp_enabled,
        }
    }
}

#[async_trait::async_trait]
impl SignInAccounts for PgSignInAccounts {
    async fn by_email(&self, email: &Email) -> Result<Option<SignInAccount>, AuthError> {
        let row: Option<SignInRow> = sqlx::query_as(&format!(
            "SELECT {SIGN_IN_COLUMNS} FROM users WHERE lower(email) = $1"
        ))
        .bind(email.as_str())
        .fetch_optional(&self.pool)
        .await
        .context("find an account by email")?;
        Ok(row.map(Into::into))
    }

    async fn by_id(&self, id: UserId) -> Result<Option<SignInAccount>, AuthError> {
        let row: Option<SignInRow> = sqlx::query_as(&format!(
            "SELECT {SIGN_IN_COLUMNS} FROM users WHERE id = $1"
        ))
        .bind(id.as_uuid())
        .fetch_optional(&self.pool)
        .await
        .context("find an account by id")?;
        Ok(row.map(Into::into))
    }
}

#[derive(sqlx::FromRow)]
struct TicketRow {
    user_id: uuid::Uuid,
    client_id: String,
    redirect_uri: String,
    scope: String,
    oauth_state: String,
    code_challenge: String,
    code_challenge_method: String,
    nonce: Option<String>,
    attempts: i32,
}

impl TryFrom<TicketRow> for Ticket {
    type Error = anyhow::Error;

    fn try_from(row: TicketRow) -> Result<Self, Self::Error> {
        Ok(Ticket {
            user: row.user_id.into(),
            request: AuthorizationRequest {
                client: ClientId::parse(&row.client_id).context("pending_totp_logins.client_id")?,
                redirect_uri: row.redirect_uri,
                scope: row.scope,
                state: row.oauth_state,
                challenge: CodeChallenge::parse(&row.code_challenge, &row.code_challenge_method)
                    .context("pending_totp_logins.code_challenge_method")?,
                nonce: row.nonce,
            },
            attempts: row.attempts,
        })
    }
}

/// `sessions`.
pub struct PgSessions {
    pool: PgPool,
}

impl PgSessions {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

const SESSION_COLUMNS: &str = "id, user_id, kind, client_id, device_id, created_at, last_used_at, \
     authenticated_at, revoked_at";

#[derive(sqlx::FromRow)]
struct SessionRow {
    id: uuid::Uuid,
    user_id: uuid::Uuid,
    kind: String,
    client_id: Option<String>,
    device_id: Option<uuid::Uuid>,
    created_at: OffsetDateTime,
    last_used_at: OffsetDateTime,
    authenticated_at: OffsetDateTime,
    revoked_at: Option<OffsetDateTime>,
}

impl TryFrom<SessionRow> for Session {
    type Error = anyhow::Error;

    fn try_from(row: SessionRow) -> Result<Self, Self::Error> {
        let kind = match (row.kind.as_str(), row.client_id) {
            ("browser", None) => SessionKind::Browser,
            ("app", Some(client)) => {
                SessionKind::App(ClientId::parse(&client).context("sessions.client_id")?)
            }
            (kind, _) => anyhow::bail!("sessions.kind {kind}, against its client_id"),
        };
        Ok(Session {
            id: row.id.into(),
            user: row.user_id.into(),
            kind,
            device: row.device_id.map(DeviceId::from),
            created_at: row.created_at,
            last_used_at: row.last_used_at,
            authenticated_at: row.authenticated_at,
            revoked_at: row.revoked_at,
        })
    }
}

#[async_trait::async_trait]
impl Sessions for PgSessions {
    async fn open(
        &self,
        user: UserId,
        kind: &SessionKind,
        now: OffsetDateTime,
    ) -> Result<SessionId, AuthError> {
        let id = SessionId::generate();
        let (kind, client) = match kind {
            SessionKind::Browser => ("browser", None),
            SessionKind::App(client) => ("app", Some(client.as_str())),
        };
        sqlx::query(
            "INSERT INTO sessions \
             (id, user_id, kind, client_id, created_at, last_used_at, authenticated_at) \
             VALUES ($1, $2, $3, $4, $5, $5, $5)",
        )
        .bind(id.as_uuid())
        .bind(user.as_uuid())
        .bind(kind)
        .bind(client)
        .bind(now)
        .execute(&self.pool)
        .await
        .context("open a session")?;
        Ok(id)
    }

    async fn find(&self, id: SessionId) -> Result<Option<Session>, AuthError> {
        let row: Option<SessionRow> = sqlx::query_as(&format!(
            "SELECT {SESSION_COLUMNS} FROM sessions WHERE id = $1"
        ))
        .bind(id.as_uuid())
        .fetch_optional(&self.pool)
        .await
        .context("find a session")?;
        Ok(row.map(Session::try_from).transpose()?)
    }

    async fn touch(&self, id: SessionId, now: OffsetDateTime) -> Result<(), AuthError> {
        sqlx::query("UPDATE sessions SET last_used_at = $2 WHERE id = $1")
            .bind(id.as_uuid())
            .bind(now)
            .execute(&self.pool)
            .await
            .context("stamp a session's use")?;
        Ok(())
    }

    async fn authenticate(&self, id: SessionId, at: OffsetDateTime) -> Result<(), AuthError> {
        sqlx::query("UPDATE sessions SET authenticated_at = $2 WHERE id = $1")
            .bind(id.as_uuid())
            .bind(at)
            .execute(&self.pool)
            .await
            .context("stamp a session's password")?;
        Ok(())
    }

    async fn revoke(
        &self,
        id: SessionId,
        reason: RevokedReason,
        now: OffsetDateTime,
    ) -> Result<bool, AuthError> {
        let revoked = sqlx::query(
            "UPDATE sessions SET revoked_at = $2, revoked_reason = $3 \
             WHERE id = $1 AND revoked_at IS NULL",
        )
        .bind(id.as_uuid())
        .bind(now)
        .bind(reason.as_str())
        .execute(&self.pool)
        .await
        .context("revoke a session")?;
        Ok(revoked.rows_affected() == 1)
    }

    async fn delete_ended(&self, before: OffsetDateTime) -> Result<usize, AuthError> {
        let deleted =
            sqlx::query("DELETE FROM sessions WHERE revoked_at < $1 OR last_used_at < $2")
                .bind(before)
                .bind(before - SESSION_IDLE)
                .execute(&self.pool)
                .await
                .context("delete the ended sessions")?;
        Ok(usize::try_from(deleted.rows_affected()).unwrap_or(usize::MAX))
    }

    async fn of_user(&self, user: UserId) -> Result<Vec<Session>, AuthError> {
        let rows: Vec<SessionRow> = sqlx::query_as(&format!(
            "SELECT {SESSION_COLUMNS} FROM sessions WHERE user_id = $1 ORDER BY created_at, id"
        ))
        .bind(user.as_uuid())
        .fetch_all(&self.pool)
        .await
        .context("list an account's sessions")?;
        sessions(rows)
    }

    async fn link(
        &self,
        id: SessionId,
        device: DeviceId,
        now: OffsetDateTime,
    ) -> Result<Vec<Session>, AuthError> {
        let mut tx = self.pool.begin().await.context("begin a link")?;
        // One link of a device at a time: two at once would each miss the other.
        sqlx::query("SELECT 1 FROM user_devices WHERE device_id = $1 FOR UPDATE")
            .bind(device.as_uuid())
            .execute(&mut *tx)
            .await
            .context("lock a device to link")?;
        let replaced: Vec<SessionRow> = sqlx::query_as(&format!(
            "UPDATE sessions SET revoked_at = $3, revoked_reason = 'replaced' \
             WHERE device_id = $2 AND id <> $1 AND revoked_at IS NULL RETURNING {SESSION_COLUMNS}"
        ))
        .bind(id.as_uuid())
        .bind(device.as_uuid())
        .bind(now)
        .fetch_all(&mut *tx)
        .await
        .context("end a device's earlier sessions")?;
        sqlx::query("UPDATE sessions SET device_id = $2 WHERE id = $1")
            .bind(id.as_uuid())
            .bind(device.as_uuid())
            .execute(&mut *tx)
            .await
            .context("link a session to its device")?;
        tx.commit().await.context("commit a link")?;
        sessions(replaced)
    }

    async fn revoke_device(
        &self,
        user: UserId,
        device: DeviceId,
        now: OffsetDateTime,
    ) -> Result<Vec<Session>, AuthError> {
        let rows: Vec<SessionRow> = sqlx::query_as(&format!(
            "UPDATE sessions SET revoked_at = $3, revoked_reason = 'device_revoked' \
             WHERE user_id = $1 AND device_id = $2 AND revoked_at IS NULL \
             RETURNING {SESSION_COLUMNS}"
        ))
        .bind(user.as_uuid())
        .bind(device.as_uuid())
        .bind(now)
        .fetch_all(&self.pool)
        .await
        .context("end a revoked device's sessions")?;
        sessions(rows)
    }

    async fn revoke_others(
        &self,
        user: UserId,
        keep: SessionId,
        now: OffsetDateTime,
    ) -> Result<Vec<Session>, AuthError> {
        let rows: Vec<SessionRow> = sqlx::query_as(&format!(
            "UPDATE sessions SET revoked_at = $3, revoked_reason = 'signed_out_elsewhere' \
             WHERE user_id = $1 AND id <> $2 AND revoked_at IS NULL RETURNING {SESSION_COLUMNS}"
        ))
        .bind(user.as_uuid())
        .bind(keep.as_uuid())
        .bind(now)
        .fetch_all(&self.pool)
        .await
        .context("end an account's other sessions")?;
        sessions(rows)
    }
}

/// `refresh_tokens`: a presentation locks its token, then its successor, so presentations of one
/// chain are judged one after the other.
pub struct PgRefreshTokens {
    pool: PgPool,
}

impl PgRefreshTokens {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

fn fresh_refresh_token() -> RefreshToken {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    RefreshToken::new(URL_SAFE_NO_PAD.encode(bytes))
}

/// A token as it is kept — a refresh token, an invitation's, a reset link's: its SHA-256 only.
fn token_digest(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

#[derive(sqlx::FromRow)]
struct RefreshRow {
    session_id: uuid::Uuid,
    client_id: String,
    rotated_at: Option<OffsetDateTime>,
    successor_hash: Option<Vec<u8>>,
}

const INSERT_REFRESH_TOKEN: &str = "INSERT INTO refresh_tokens \
         (token_hash, session_id, client_id, created_at) VALUES ($1, $2, $3, $4)";

#[async_trait::async_trait]
impl RefreshTokens for PgRefreshTokens {
    async fn start(
        &self,
        session: SessionId,
        client: &ClientId,
        now: OffsetDateTime,
    ) -> Result<RefreshToken, AuthError> {
        let token = fresh_refresh_token();
        sqlx::query(INSERT_REFRESH_TOKEN)
            .bind(token_digest(token.as_str()))
            .bind(session.as_uuid())
            .bind(client.as_str())
            .bind(now)
            .execute(&self.pool)
            .await
            .context("start a refresh token chain")?;
        Ok(token)
    }

    async fn rotate(
        &self,
        token: &RefreshToken,
        client: &ClientId,
        now: OffsetDateTime,
    ) -> Result<Rotation, AuthError> {
        let hash = token_digest(token.as_str());
        let mut tx = self.pool.begin().await.context("begin a rotation")?;
        let row: Option<RefreshRow> = sqlx::query_as(
            "SELECT session_id, client_id, rotated_at, successor_hash FROM refresh_tokens \
             WHERE token_hash = $1 FOR UPDATE",
        )
        .bind(&hash)
        .fetch_optional(&mut *tx)
        .await
        .context("find a refresh token")?;
        let Some(row) = row else {
            return Ok(Rotation::Refused);
        };
        let successor_unused = match &row.successor_hash {
            Some(successor) => sqlx::query_scalar::<_, bool>(
                "SELECT rotated_at IS NULL FROM refresh_tokens WHERE token_hash = $1 FOR UPDATE",
            )
            .bind(successor)
            .fetch_optional(&mut *tx)
            .await
            .context("find a refresh token's successor")?
            .unwrap_or(false),
            None => false,
        };
        let session = SessionId::from(row.session_id);
        let link = RefreshLink {
            session,
            client: ClientId::parse(&row.client_id).context("refresh_tokens.client_id")?,
            rotated_at: row.rotated_at,
            successor_unused,
        };
        match link.presented(client, now) {
            Presentation::Refused => return Ok(Rotation::Refused),
            Presentation::Reuse => return Ok(Rotation::Reused { session }),
            Presentation::Rotate => {}
            Presentation::Retry => {
                sqlx::query(
                    "UPDATE refresh_tokens SET rotated_at = $2, successor_hash = NULL \
                     WHERE token_hash = $1",
                )
                .bind(&row.successor_hash)
                .bind(now)
                .execute(&mut *tx)
                .await
                .context("replace a refresh token's successor")?;
            }
        }
        let successor = fresh_refresh_token();
        let successor_hash = token_digest(successor.as_str());
        sqlx::query(INSERT_REFRESH_TOKEN)
            .bind(&successor_hash)
            .bind(session.as_uuid())
            .bind(client.as_str())
            .bind(now)
            .execute(&mut *tx)
            .await
            .context("insert a refresh token's successor")?;
        // A retry keeps the first rotation's time, so the grace never stretches.
        sqlx::query(
            "UPDATE refresh_tokens \
             SET rotated_at = COALESCE(rotated_at, $2), successor_hash = $3 \
             WHERE token_hash = $1",
        )
        .bind(&hash)
        .bind(now)
        .bind(&successor_hash)
        .execute(&mut *tx)
        .await
        .context("rotate a refresh token")?;
        tx.commit().await.context("commit a rotation")?;
        Ok(Rotation::Rotated { session, successor })
    }

    async fn session_of(
        &self,
        token: &RefreshToken,
        client: &ClientId,
    ) -> Result<Option<SessionId>, AuthError> {
        let session: Option<uuid::Uuid> = sqlx::query_scalar(
            "SELECT session_id FROM refresh_tokens WHERE token_hash = $1 AND client_id = $2",
        )
        .bind(token_digest(token.as_str()))
        .bind(client.as_str())
        .fetch_optional(&self.pool)
        .await
        .context("find a refresh token's session")?;
        Ok(session.map(SessionId::from))
    }

    async fn delete_unused(&self, before: OffsetDateTime) -> Result<usize, AuthError> {
        let deleted =
            sqlx::query("DELETE FROM refresh_tokens WHERE COALESCE(rotated_at, created_at) < $1")
                .bind(before)
                .execute(&self.pool)
                .await
                .context("delete the unused refresh tokens")?;
        Ok(usize::try_from(deleted.rows_affected()).unwrap_or(usize::MAX))
    }
}

fn sessions(rows: Vec<SessionRow>) -> Result<Vec<Session>, AuthError> {
    Ok(rows
        .into_iter()
        .map(Session::try_from)
        .collect::<Result<_, _>>()?)
}

/// `client_sign_ins`: one row per account and app.
pub struct PgClientSignIns {
    pool: PgPool,
}

impl PgClientSignIns {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl ClientSignIns for PgClientSignIns {
    async fn remember(&self, sign_in: &ClientSignIn, at: OffsetDateTime) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO client_sign_ins (user_id, client_id, offline_access, signed_in_at) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (user_id, client_id) DO UPDATE SET \
                 offline_access = client_sign_ins.offline_access OR EXCLUDED.offline_access, \
                 signed_in_at = EXCLUDED.signed_in_at",
        )
        .bind(sign_in.user.as_uuid())
        .bind(sign_in.client.as_str())
        .bind(sign_in.offline_access)
        .bind(at)
        .execute(&self.pool)
        .await
        .context("remember an app signed in to")?;
        Ok(())
    }

    async fn find(
        &self,
        user: UserId,
        client: &ClientId,
    ) -> Result<Option<ClientSignIn>, AuthError> {
        let offline_access: Option<bool> = sqlx::query_scalar(
            "SELECT offline_access FROM client_sign_ins WHERE user_id = $1 AND client_id = $2",
        )
        .bind(user.as_uuid())
        .bind(client.as_str())
        .fetch_optional(&self.pool)
        .await
        .context("find an app signed in to")?;
        Ok(offline_access.map(|offline_access| ClientSignIn {
            user,
            client: client.clone(),
            offline_access,
        }))
    }
}

/// `pending_totp_logins`.
pub struct PgLoginTickets {
    pool: PgPool,
}

impl PgLoginTickets {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl LoginTickets for PgLoginTickets {
    async fn open(
        &self,
        user: UserId,
        request: &AuthorizationRequest,
        expires_at: OffsetDateTime,
    ) -> Result<TicketId, AuthError> {
        let mut tx = self.pool.begin().await.context("begin a login ticket")?;
        sqlx::query(
            "UPDATE pending_totp_logins SET consumed_at = now() \
             WHERE user_id = $1 AND consumed_at IS NULL",
        )
        .bind(user.as_uuid())
        .execute(&mut *tx)
        .await
        .context("close an account's open login tickets")?;
        let id: uuid::Uuid = sqlx::query_scalar(
            "INSERT INTO pending_totp_logins \
                 (user_id, client_id, redirect_uri, scope, oauth_state, code_challenge, \
                  code_challenge_method, nonce, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, 'S256', $7, $8) RETURNING id",
        )
        .bind(user.as_uuid())
        .bind(request.client.as_str())
        .bind(&request.redirect_uri)
        .bind(&request.scope)
        .bind(&request.state)
        .bind(request.challenge.as_str())
        .bind(&request.nonce)
        .bind(expires_at)
        .fetch_one(&mut *tx)
        .await
        .context("open a login ticket")?;
        tx.commit().await.context("commit a login ticket")?;
        Ok(id.into())
    }

    async fn find(
        &self,
        ticket: TicketId,
        now: OffsetDateTime,
    ) -> Result<Option<Ticket>, AuthError> {
        let row: Option<TicketRow> = sqlx::query_as(
            "SELECT user_id, client_id, redirect_uri, scope, oauth_state, code_challenge, \
                    code_challenge_method, nonce, attempts \
             FROM pending_totp_logins \
             WHERE id = $1 AND consumed_at IS NULL AND expires_at > $2",
        )
        .bind(ticket.as_uuid())
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .context("find a login ticket")?;
        Ok(row.map(Ticket::try_from).transpose()?)
    }

    async fn reserve_attempt(
        &self,
        ticket: TicketId,
        now: OffsetDateTime,
    ) -> Result<TicketAttempt, AuthError> {
        // Counted by the statement that checks the cap: no two guesses read the same count.
        let reserved: Option<TicketRow> = sqlx::query_as(
            "UPDATE pending_totp_logins SET attempts = attempts + 1 \
             WHERE id = $1 AND consumed_at IS NULL AND expires_at > $2 AND attempts < $3 \
             RETURNING user_id, client_id, redirect_uri, scope, oauth_state, code_challenge, \
                       code_challenge_method, nonce, attempts",
        )
        .bind(ticket.as_uuid())
        .bind(now)
        .bind(TICKET_ATTEMPTS)
        .fetch_optional(&self.pool)
        .await
        .context("reserve an attempt on a login ticket")?;
        if let Some(row) = reserved {
            return Ok(TicketAttempt::Open(Ticket::try_from(row)?));
        }
        let open: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM pending_totp_logins \
                            WHERE id = $1 AND consumed_at IS NULL AND expires_at > $2)",
        )
        .bind(ticket.as_uuid())
        .bind(now)
        .fetch_one(&self.pool)
        .await
        .context("find a login ticket")?;
        Ok(if open {
            TicketAttempt::Exhausted
        } else {
            TicketAttempt::Gone
        })
    }

    async fn consume(&self, ticket: TicketId) -> Result<bool, AuthError> {
        let spent = sqlx::query(
            "UPDATE pending_totp_logins SET consumed_at = now() \
             WHERE id = $1 AND consumed_at IS NULL",
        )
        .bind(ticket.as_uuid())
        .execute(&self.pool)
        .await
        .context("spend a login ticket")?
        .rows_affected();
        Ok(spent == 1)
    }

    async fn delete_spent(
        &self,
        now: OffsetDateTime,
        opened_before: OffsetDateTime,
    ) -> Result<usize, AuthError> {
        let deleted = sqlx::query(
            "DELETE FROM pending_totp_logins \
             WHERE (consumed_at IS NOT NULL OR expires_at < $1) AND created_at < $2",
        )
        .bind(now)
        .bind(opened_before)
        .execute(&self.pool)
        .await
        .context("delete spent login tickets")?
        .rows_affected();
        Ok(usize::try_from(deleted).unwrap_or_default())
    }
}

/// `email_verification_codes`: only an HMAC of each code is kept, under a pepper the database
/// never sees.
pub struct PgSignupCodes {
    pool: PgPool,
    pepper: Arc<Vec<u8>>,
}

impl PgSignupCodes {
    pub fn new(pool: PgPool, pepper: Arc<Vec<u8>>) -> Self {
        Self { pool, pepper }
    }

    fn mac(&self, code: &OtpCode) -> Hmac<Sha256> {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.pepper).expect("HMAC accepts any key length");
        mac.update(code.as_str().as_bytes());
        mac
    }

    fn hash(&self, code: &OtpCode) -> Vec<u8> {
        self.mac(code).finalize().into_bytes().to_vec()
    }
}

/// Uniform digits: a byte of 250 or more is drawn again, or `% 10` would favour 0–5.
fn six_digits() -> OtpCode {
    let mut digits = String::with_capacity(OtpCode::LEN);
    let mut byte = [0u8; 1];
    while digits.len() < OtpCode::LEN {
        OsRng.fill_bytes(&mut byte);
        if byte[0] < 250 {
            digits.push(char::from(b'0' + byte[0] % 10));
        }
    }
    OtpCode::parse(&digits).expect("six digits")
}

#[async_trait::async_trait]
impl SignupCodes for PgSignupCodes {
    async fn issue(&self, user: UserId, expires_at: OffsetDateTime) -> Result<OtpCode, AuthError> {
        let code = six_digits();
        let mut tx = self.pool.begin().await.context("begin a signup code")?;
        sqlx::query(
            "UPDATE email_verification_codes SET consumed_at = now() \
             WHERE user_id = $1 AND consumed_at IS NULL",
        )
        .bind(user.as_uuid())
        .execute(&mut *tx)
        .await
        .context("retire an account's signup codes")?;
        sqlx::query(
            "INSERT INTO email_verification_codes (user_id, code_hash, expires_at) \
             VALUES ($1, $2, $3)",
        )
        .bind(user.as_uuid())
        .bind(self.hash(&code))
        .bind(expires_at)
        .execute(&mut *tx)
        .await
        .context("store a signup code")?;
        tx.commit().await.context("commit a signup code")?;
        Ok(code)
    }

    async fn issued_since(&self, user: UserId, since: OffsetDateTime) -> Result<usize, AuthError> {
        let issued: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM email_verification_codes WHERE user_id = $1 AND created_at > $2",
        )
        .bind(user.as_uuid())
        .bind(since)
        .fetch_one(&self.pool)
        .await
        .context("count the signup codes issued lately")?;
        Ok(usize::try_from(issued).unwrap_or_default())
    }

    async fn attempt(
        &self,
        user: UserId,
        code: &OtpCode,
        now: OffsetDateTime,
    ) -> Result<CodeAttempt, AuthError> {
        let mut tx = self.pool.begin().await.context("begin a code attempt")?;
        // Locked until the attempt is counted: parallel guesses queue up behind it, so the cap
        // holds for all of them.
        let live: Option<(uuid::Uuid, Vec<u8>, i32)> = sqlx::query_as(
            "SELECT id, code_hash, attempts FROM email_verification_codes \
             WHERE user_id = $1 AND consumed_at IS NULL AND expires_at > $2 \
             ORDER BY created_at DESC LIMIT 1 FOR UPDATE",
        )
        .bind(user.as_uuid())
        .bind(now)
        .fetch_optional(&mut *tx)
        .await
        .context("find an account's live signup code")?;
        let Some((id, code_hash, attempts)) = live else {
            return Ok(CodeAttempt::NoCode);
        };
        if attempts >= CODE_ATTEMPTS {
            return Ok(CodeAttempt::Exhausted);
        }
        if self.mac(code).verify_slice(&code_hash).is_err() {
            sqlx::query(
                "UPDATE email_verification_codes SET attempts = attempts + 1 WHERE id = $1",
            )
            .bind(id)
            .execute(&mut *tx)
            .await
            .context("count a wrong signup code")?;
            tx.commit().await.context("commit a wrong signup code")?;
            return Ok(CodeAttempt::Wrong {
                left: CODE_ATTEMPTS - attempts - 1,
            });
        }
        sqlx::query("UPDATE email_verification_codes SET consumed_at = now() WHERE id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await
            .context("spend a signup code")?;
        sqlx::query("UPDATE users SET email_verified_at = now(), updated_at = now() WHERE id = $1")
            .bind(user.as_uuid())
            .execute(&mut *tx)
            .await
            .context("confirm an account's address")?;
        tx.commit().await.context("commit a confirmation")?;
        Ok(CodeAttempt::Confirmed)
    }

    async fn delete_spent(
        &self,
        now: OffsetDateTime,
        issued_before: OffsetDateTime,
    ) -> Result<usize, AuthError> {
        let deleted = sqlx::query(
            "DELETE FROM email_verification_codes \
             WHERE (consumed_at IS NOT NULL OR expires_at < $1) AND created_at < $2",
        )
        .bind(now)
        .bind(issued_before)
        .execute(&self.pool)
        .await
        .context("delete spent signup codes")?
        .rows_affected();
        Ok(usize::try_from(deleted).unwrap_or_default())
    }
}

/// `users`, as registering writes them.
pub struct PgSignUps {
    pool: PgPool,
}

impl PgSignUps {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    async fn insert(
        &self,
        account: &NewAccount,
        is_admin: bool,
        admitted_at: Option<OffsetDateTime>,
    ) -> Result<Registration, AuthError> {
        let mut connection = self.pool.acquire().await.context("acquire a connection")?;
        insert_account(&mut connection, account, is_admin, admitted_at, None).await
    }
}

/// The account, unless its address or its handle is another's already.
async fn insert_account(
    connection: &mut sqlx::PgConnection,
    account: &NewAccount,
    is_admin: bool,
    admitted_at: Option<OffsetDateTime>,
    invited_by: Option<UserId>,
) -> Result<Registration, AuthError> {
    let created = sqlx::query(
        "INSERT INTO users \
             (id, username, email, password_hash, display_name, actor_uri, inbox_url, \
              outbox_url, is_admin, admitted_at, invited_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $6 || '/inbox', $6 || '/outbox', $7, $8, $9)",
    )
    .bind(account.id.as_uuid())
    .bind(account.username.as_str())
    .bind(account.email.as_str())
    .bind(account.password_hash.as_str())
    .bind(&account.display_name)
    .bind(account.actor_uri.as_str())
    .bind(is_admin)
    .bind(admitted_at)
    .bind(invited_by.map(|user| user.as_uuid()))
    .execute(connection)
    .await;
    match created {
        Ok(_) => Ok(Registration::Created),
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => match e.constraint() {
            Some("users_email_key" | "users_email_lower_key") => Ok(Registration::EmailTaken),
            Some("users_username_key" | "users_actor_uri_key") => Ok(Registration::HandleTaken),
            _ => Err(anyhow::Error::from(sqlx::Error::Database(e))
                .context("create an account")
                .into()),
        },
        Err(e) => Err(anyhow::Error::from(e).context("create an account").into()),
    }
}

#[derive(sqlx::FromRow)]
struct AdminFactsRow {
    holder_is_admin: Option<bool>,
    admin_exists: bool,
}

#[async_trait::async_trait]
impl SignUps for PgSignUps {
    async fn create(&self, account: &NewAccount) -> Result<Registration, AuthError> {
        self.insert(account, false, None).await
    }

    async fn create_admin(
        &self,
        account: &NewAccount,
        admitted_at: OffsetDateTime,
    ) -> Result<Registration, AuthError> {
        self.insert(account, true, Some(admitted_at)).await
    }

    async fn create_invited(
        &self,
        account: &NewAccount,
        invitation: InvitationId,
        now: OffsetDateTime,
    ) -> Result<Registration, AuthError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .context("begin an invited sign-up")?;
        // Spent first: a sign-up racing for the same invitation waits on its row, then finds it
        // spent.
        let inviter: Option<uuid::Uuid> = sqlx::query_scalar(
            "UPDATE invitations SET used_at = $2 \
             WHERE id = $1 AND used_at IS NULL AND revoked_at IS NULL AND expires_at > $2 \
             RETURNING created_by",
        )
        .bind(invitation.as_uuid())
        .bind(now)
        .fetch_optional(&mut *tx)
        .await
        .context("spend an invitation")?;
        let Some(inviter) = inviter else {
            return Ok(Registration::InvitationSpent);
        };
        let registration =
            insert_account(&mut tx, account, false, Some(now), Some(inviter.into())).await?;
        if registration != Registration::Created {
            return Ok(registration);
        }
        sqlx::query("UPDATE invitations SET used_by = $2 WHERE id = $1")
            .bind(invitation.as_uuid())
            .bind(account.id.as_uuid())
            .execute(&mut *tx)
            .await
            .context("record who an invitation let in")?;
        tx.commit().await.context("commit an invited sign-up")?;
        Ok(Registration::Created)
    }

    async fn admin_facts(&self, address: Option<&Email>) -> Result<AdminFacts, AuthError> {
        let row: AdminFactsRow = sqlx::query_as(
            "SELECT (SELECT is_admin FROM users WHERE lower(email) = $1) AS holder_is_admin, \
                    EXISTS (SELECT 1 FROM users WHERE is_admin) AS admin_exists",
        )
        .bind(address.map(Email::as_str))
        .fetch_one(&self.pool)
        .await
        .context("read the admin facts")?;
        Ok(AdminFacts {
            holder: match row.holder_is_admin {
                None => AddressHolder::Nobody,
                Some(true) => AddressHolder::Admin,
                Some(false) => AddressHolder::NotAdmin,
            },
            admin_exists: row.admin_exists,
        })
    }

    async fn delete_unverified(&self, created_before: OffsetDateTime) -> Result<usize, AuthError> {
        let deleted = sqlx::query(
            "DELETE FROM users \
             WHERE email_verified_at IS NULL AND admitted_at IS NULL AND created_at < $1",
        )
        .bind(created_before)
        .execute(&self.pool)
        .await
        .context("delete the accounts never confirmed")?
        .rows_affected();
        Ok(usize::try_from(deleted).unwrap_or_default())
    }
}

/// `invitations`: a token is kept as its SHA-256, like a refresh token; a spend or a revocation
/// is a guarded `UPDATE`, so it happens once.
pub struct PgInvitations {
    pool: PgPool,
}

impl PgInvitations {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

const INVITATION_COLUMNS: &str = "i.id, i.created_by, i.created_at, i.expires_at, i.used_at, \
     i.revoked_at, c.display_name AS inviter";

#[derive(sqlx::FromRow)]
struct InvitationRow {
    id: uuid::Uuid,
    created_by: uuid::Uuid,
    created_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    used_at: Option<OffsetDateTime>,
    revoked_at: Option<OffsetDateTime>,
    inviter: Option<String>,
}

impl InvitationRow {
    /// The invitation, while it is open at `now`.
    fn open(self, now: OffsetDateTime) -> Option<OpenInvitation> {
        let invitation = Invitation {
            id: self.id.into(),
            created_by: self.created_by.into(),
            created_at: self.created_at,
            expires_at: self.expires_at,
            used_at: self.used_at,
            revoked_at: self.revoked_at,
        };
        invitation.is_open(now).then_some(OpenInvitation {
            id: invitation.id,
            inviter: self.inviter,
            created_at: invitation.created_at,
            expires_at: invitation.expires_at,
        })
    }
}

#[async_trait::async_trait]
impl Invitations for PgInvitations {
    async fn issue(
        &self,
        by: UserId,
        now: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) -> Result<(InvitationId, InvitationToken), AuthError> {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let token = InvitationToken::from_bytes(bytes);
        let id = InvitationId::generate();
        sqlx::query(
            "INSERT INTO invitations (id, token_hash, created_by, created_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(id.as_uuid())
        .bind(token_digest(token.as_str()))
        .bind(by.as_uuid())
        .bind(now)
        .bind(expires_at)
        .execute(&self.pool)
        .await
        .context("create an invitation")?;
        Ok((id, token))
    }

    async fn find_open(
        &self,
        token: &InvitationToken,
        now: OffsetDateTime,
    ) -> Result<Option<OpenInvitation>, AuthError> {
        let row: Option<InvitationRow> = sqlx::query_as(&format!(
            "SELECT {INVITATION_COLUMNS} \
             FROM invitations i JOIN users c ON c.id = i.created_by \
             WHERE i.token_hash = $1"
        ))
        .bind(token_digest(token.as_str()))
        .fetch_optional(&self.pool)
        .await
        .context("find an invitation")?;
        Ok(row.and_then(|row| row.open(now)))
    }

    async fn list_open(&self, now: OffsetDateTime) -> Result<Vec<OpenInvitation>, AuthError> {
        // Every unused, unrevoked one, then the rule decides: the sweep keeps the table small.
        let rows: Vec<InvitationRow> = sqlx::query_as(&format!(
            "SELECT {INVITATION_COLUMNS} \
             FROM invitations i JOIN users c ON c.id = i.created_by \
             WHERE i.used_at IS NULL AND i.revoked_at IS NULL \
             ORDER BY i.created_at DESC, i.id DESC"
        ))
        .fetch_all(&self.pool)
        .await
        .context("list the open invitations")?;
        Ok(rows.into_iter().filter_map(|row| row.open(now)).collect())
    }

    async fn revoke(&self, id: InvitationId, now: OffsetDateTime) -> Result<bool, AuthError> {
        let revoked = sqlx::query(
            "UPDATE invitations SET revoked_at = $2 \
             WHERE id = $1 AND used_at IS NULL AND revoked_at IS NULL AND expires_at > $2",
        )
        .bind(id.as_uuid())
        .bind(now)
        .execute(&self.pool)
        .await
        .context("revoke an invitation")?;
        Ok(revoked.rows_affected() == 1)
    }

    async fn delete_ended(&self, before: OffsetDateTime) -> Result<usize, AuthError> {
        // `LEAST` skips the NULLs: whichever of used, revoked and expired came first.
        let deleted = sqlx::query(
            "DELETE FROM invitations WHERE LEAST(used_at, revoked_at, expires_at) < $1",
        )
        .bind(before)
        .execute(&self.pool)
        .await
        .context("delete the ended invitations")?
        .rows_affected();
        Ok(usize::try_from(deleted).unwrap_or(usize::MAX))
    }
}

/// `password_resets`: a token is kept as its SHA-256, like an invitation's; a spend is a guarded
/// `UPDATE`, so it happens once. A link the account asked for by mail has no `created_by`.
pub struct PgPasswordResets {
    pool: PgPool,
}

impl PgPasswordResets {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

/// Locks the member's account until the transaction ends. Issuing and resetting both take it
/// first, so the two at once queue up instead of deadlocking on each other's rows.
async fn lock_member(connection: &mut sqlx::PgConnection, member: UserId) -> Result<(), AuthError> {
    sqlx::query("SELECT 1 FROM users WHERE id = $1 FOR NO KEY UPDATE")
        .bind(member.as_uuid())
        .execute(connection)
        .await
        .context("lock a member's account")?;
    Ok(())
}

/// A new link for `member` by `by` — nobody, when the account asked for it —, the one they had
/// open replaced, within the caller's transaction: it holds the member's lock already. The
/// replaced link names the new one in `replaced_by`, which `withdraw` finds it by.
async fn open_link(
    connection: &mut sqlx::PgConnection,
    member: UserId,
    by: Option<UserId>,
    now: OffsetDateTime,
    expires_at: OffsetDateTime,
) -> Result<ResetToken, AuthError> {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let token = ResetToken::from_bytes(bytes);
    let id = uuid::Uuid::new_v4();
    sqlx::query(
        "UPDATE password_resets SET replaced_at = $2, replaced_by = $3 \
         WHERE user_id = $1 AND used_at IS NULL AND replaced_at IS NULL",
    )
    .bind(member.as_uuid())
    .bind(now)
    .bind(id)
    .execute(&mut *connection)
    .await
    .context("replace an account's open reset link")?;
    sqlx::query(
        "INSERT INTO password_resets (id, token_hash, user_id, created_by, created_at, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(id)
    .bind(token_digest(token.as_str()))
    .bind(member.as_uuid())
    .bind(by.map(|by| by.as_uuid()))
    .bind(now)
    .bind(expires_at)
    .execute(&mut *connection)
    .await
    .context("create a reset link")?;
    Ok(token)
}

#[derive(sqlx::FromRow)]
struct ResetRow {
    user_id: uuid::Uuid,
    created_by: Option<uuid::Uuid>,
    created_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    used_at: Option<OffsetDateTime>,
    replaced_at: Option<OffsetDateTime>,
    display_name: Option<String>,
    email: String,
}

impl ResetRow {
    /// The link, while it is open at `now`.
    fn open(self, now: OffsetDateTime) -> Option<OpenReset> {
        let reset = PasswordReset {
            member: self.user_id.into(),
            created_by: self.created_by.map(UserId::from),
            created_at: self.created_at,
            expires_at: self.expires_at,
            used_at: self.used_at,
            replaced_at: self.replaced_at,
        };
        reset.is_open(now).then(|| OpenReset {
            member: reset.member,
            display_name: self.display_name,
            email: self.email,
            by: reset.by(),
            expires_at: reset.expires_at,
        })
    }
}

#[async_trait::async_trait]
impl PasswordResets for PgPasswordResets {
    async fn issue(
        &self,
        member: UserId,
        by: UserId,
        now: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) -> Result<ResetToken, AuthError> {
        let mut tx = self.pool.begin().await.context("begin a reset link")?;
        lock_member(&mut tx, member).await?;
        let token = open_link(&mut tx, member, Some(by), now, expires_at).await?;
        tx.commit().await.context("commit a reset link")?;
        Ok(token)
    }

    async fn request(
        &self,
        member: UserId,
        now: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) -> Result<Option<ResetToken>, AuthError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .context("begin a reset link asked for")?;
        // Counted under the account's lock: requests at once queue up, and none passes the limit.
        lock_member(&mut tx, member).await?;
        let asked: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM password_resets \
             WHERE user_id = $1 AND created_by IS NULL AND created_at > $2",
        )
        .bind(member.as_uuid())
        .bind(now - RESET_REQUEST_WINDOW)
        .fetch_one(&mut *tx)
        .await
        .context("count the reset links an account asked for")?;
        if !may_request_reset(usize::try_from(asked).unwrap_or(usize::MAX)) {
            return Ok(None);
        }
        let token = open_link(&mut tx, member, None, now, expires_at).await?;
        tx.commit().await.context("commit a reset link asked for")?;
        Ok(Some(token))
    }

    async fn withdraw(&self, token: &ResetToken, now: OffsetDateTime) -> Result<(), AuthError> {
        let token_hash = token_digest(token.as_str());
        let mut tx = self
            .pool
            .begin()
            .await
            .context("begin withdrawing a reset link")?;
        let named: Option<uuid::Uuid> =
            sqlx::query_scalar("SELECT user_id FROM password_resets WHERE token_hash = $1")
                .bind(&token_hash)
                .fetch_optional(&mut *tx)
                .await
                .context("find a reset link's account")?;
        let Some(named) = named else {
            return Ok(());
        };
        lock_member(&mut tx, named.into()).await?;
        // Deleted first: the link it replaced may then be the one open link again.
        let withdrawn: Option<(uuid::Uuid, uuid::Uuid, bool)> = sqlx::query_as(
            "DELETE FROM password_resets \
             WHERE token_hash = $1 AND used_at IS NULL AND created_by IS NULL \
             RETURNING id, user_id, replaced_at IS NULL",
        )
        .bind(&token_hash)
        .fetch_optional(&mut *tx)
        .await
        .context("withdraw a reset link")?;
        if let Some((id, member, newest)) = withdrawn
            && newest
        {
            sqlx::query(
                "UPDATE password_resets SET replaced_at = NULL, replaced_by = NULL \
                 WHERE user_id = $1 AND replaced_by = $2 AND used_at IS NULL AND expires_at > $3",
            )
            .bind(member)
            .bind(id)
            .bind(now)
            .execute(&mut *tx)
            .await
            .context("give back the reset link a withdrawn one replaced")?;
        }
        tx.commit()
            .await
            .context("commit withdrawing a reset link")?;
        Ok(())
    }

    async fn find_open(
        &self,
        token: &ResetToken,
        now: OffsetDateTime,
    ) -> Result<Option<OpenReset>, AuthError> {
        let row: Option<ResetRow> = sqlx::query_as(
            "SELECT r.user_id, r.created_by, r.created_at, r.expires_at, r.used_at, r.replaced_at, \
                    u.display_name, u.email \
             FROM password_resets r JOIN users u ON u.id = r.user_id \
             WHERE r.token_hash = $1",
        )
        .bind(token_digest(token.as_str()))
        .fetch_optional(&self.pool)
        .await
        .context("find a reset link")?;
        Ok(row.and_then(|row| row.open(now)))
    }

    async fn reset(
        &self,
        token: &ResetToken,
        hash: &PasswordHash,
        now: OffsetDateTime,
    ) -> Result<PasswordChange, AuthError> {
        let token_hash = token_digest(token.as_str());
        let mut tx = self.pool.begin().await.context("begin a password reset")?;
        let named: Option<uuid::Uuid> =
            sqlx::query_scalar("SELECT user_id FROM password_resets WHERE token_hash = $1")
                .bind(&token_hash)
                .fetch_optional(&mut *tx)
                .await
                .context("find a reset link's member")?;
        let Some(named) = named else {
            return Ok(PasswordChange::LinkUnusable);
        };
        lock_member(&mut tx, named.into()).await?;
        // Spent first: a second submission of the link waits on the account, then finds it used.
        let spent: Option<uuid::Uuid> = sqlx::query_scalar(
            "UPDATE password_resets SET used_at = $2 \
             WHERE token_hash = $1 AND used_at IS NULL AND replaced_at IS NULL AND expires_at > $2 \
             RETURNING user_id",
        )
        .bind(&token_hash)
        .bind(now)
        .fetch_optional(&mut *tx)
        .await
        .context("spend a reset link")?;
        let Some(member) = spent.map(UserId::from) else {
            return Ok(PasswordChange::LinkUnusable);
        };
        sqlx::query("UPDATE users SET password_hash = $2, updated_at = now() WHERE id = $1")
            .bind(member.as_uuid())
            .bind(hash.as_str())
            .execute(&mut *tx)
            .await
            .context("set a member's new password")?;
        let ended: Vec<SessionRow> = sqlx::query_as(&format!(
            "UPDATE sessions SET revoked_at = $2, revoked_reason = 'password_reset' \
             WHERE user_id = $1 AND revoked_at IS NULL RETURNING {SESSION_COLUMNS}"
        ))
        .bind(member.as_uuid())
        .bind(now)
        .fetch_all(&mut *tx)
        .await
        .context("end a member's sessions on a password reset")?;
        sqlx::query(
            "UPDATE pending_totp_logins SET consumed_at = $2 \
             WHERE user_id = $1 AND consumed_at IS NULL",
        )
        .bind(member.as_uuid())
        .bind(now)
        .execute(&mut *tx)
        .await
        .context("close a member's second-factor tickets on a password reset")?;
        tx.commit().await.context("commit a password reset")?;
        Ok(PasswordChange::Changed {
            member,
            ended: sessions(ended)?,
        })
    }

    async fn delete_ended(&self, before: OffsetDateTime) -> Result<usize, AuthError> {
        // `LEAST` skips the NULLs: whichever of used, replaced and expired came first.
        let deleted = sqlx::query(
            "DELETE FROM password_resets WHERE LEAST(used_at, replaced_at, expires_at) < $1",
        )
        .bind(before)
        .execute(&self.pool)
        .await
        .context("delete the ended reset links")?
        .rows_affected();
        Ok(usize::try_from(deleted).unwrap_or(usize::MAX))
    }
}

/// `users` with their sessions, as the admins list them.
pub struct PgInstanceMembers {
    pool: PgPool,
}

impl PgInstanceMembers {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(sqlx::FromRow)]
struct MemberRow {
    id: uuid::Uuid,
    actor_uri: Option<String>,
    display_name: Option<String>,
    is_admin: bool,
    last_active_at: Option<OffsetDateTime>,
}

impl TryFrom<MemberRow> for InstanceMember {
    type Error = anyhow::Error;

    fn try_from(row: MemberRow) -> Result<Self, Self::Error> {
        Ok(InstanceMember {
            id: row.id.into(),
            actor: row
                .actor_uri
                .map(|uri| ActorUri::parse(&uri))
                .transpose()
                .context("users.actor_uri")?,
            display_name: row.display_name,
            admin: row.is_admin,
            last_active_at: row.last_active_at,
        })
    }
}

#[async_trait::async_trait]
impl InstanceMembers for PgInstanceMembers {
    async fn list(&self, now: OffsetDateTime) -> Result<Vec<InstanceMember>, AuthError> {
        // A live session is unrevoked and used within `SESSION_IDLE`, as `Session::is_live` says;
        // a member is an account that needs no code (`SignInAccount::needs_code`).
        let rows: Vec<MemberRow> = sqlx::query_as(
            "SELECT u.id, u.actor_uri, u.display_name, u.is_admin, \
                    MAX(s.last_used_at) FILTER (WHERE s.revoked_at IS NULL AND s.last_used_at > $1) \
                        AS last_active_at \
             FROM users u LEFT JOIN sessions s ON s.user_id = u.id \
             WHERE u.email_verified_at IS NOT NULL OR u.admitted_at IS NOT NULL \
             GROUP BY u.id \
             ORDER BY last_active_at DESC NULLS LAST, u.id",
        )
        .bind(now - SESSION_IDLE)
        .fetch_all(&self.pool)
        .await
        .context("list the members")?;
        Ok(rows
            .into_iter()
            .map(InstanceMember::try_from)
            .collect::<Result<_, _>>()?)
    }
}

/// `users.totp_secret` / `totp_enabled`, `pending_totp_enrollments` and `recovery_codes`: a
/// recovery code is kept only as an HMAC under the pepper, like a signup code.
pub struct PgSecondFactors {
    pool: PgPool,
    pepper: Arc<Vec<u8>>,
}

impl PgSecondFactors {
    pub fn new(pool: PgPool, pepper: Arc<Vec<u8>>) -> Self {
        Self { pool, pepper }
    }

    /// A fresh set in place of the account's codes, in the caller's transaction.
    async fn store_recovery_codes(
        &self,
        tx: &mut sqlx::PgConnection,
        user: UserId,
    ) -> Result<Vec<String>, AuthError> {
        let codes: Vec<String> = (0..RECOVERY_CODES).map(|_| recovery_code()).collect();
        sqlx::query("DELETE FROM recovery_codes WHERE user_id = $1")
            .bind(user.as_uuid())
            .execute(&mut *tx)
            .await
            .context("drop the old recovery codes")?;
        for code in &codes {
            sqlx::query("INSERT INTO recovery_codes (user_id, code_hash) VALUES ($1, $2)")
                .bind(user.as_uuid())
                .bind(self.hash(code))
                .execute(&mut *tx)
                .await
                .context("store a recovery code")?;
        }
        Ok(codes)
    }

    fn hash(&self, code: &str) -> Vec<u8> {
        let normalized: String = code
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .flat_map(char::to_uppercase)
            .collect();
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.pepper).expect("HMAC accepts any key length");
        mac.update(normalized.as_bytes());
        mac.finalize().into_bytes().to_vec()
    }
}

/// Crockford-like, without the characters read as others: `0 1 I L O U`.
const RECOVERY_ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTVWXYZ23456789";

/// `XXXXX-XXXXX`; the dash is for reading, and ignored when checked.
fn recovery_code() -> String {
    let mut bytes = [0u8; 10];
    OsRng.fill_bytes(&mut bytes);
    let raw: String = bytes
        .iter()
        .map(|b| char::from(RECOVERY_ALPHABET[usize::from(*b) % RECOVERY_ALPHABET.len()]))
        .collect();
    format!("{}-{}", &raw[..5], &raw[5..])
}

fn secret_of(bytes: Vec<u8>) -> Result<TotpSecret, AuthError> {
    Ok(TotpSecret::parse(bytes).context("a stored TOTP secret")?)
}

#[async_trait::async_trait]
impl SecondFactors for PgSecondFactors {
    async fn secret(&self, user: UserId) -> Result<Option<TotpSecret>, AuthError> {
        let secret: Option<Option<Vec<u8>>> =
            sqlx::query_scalar("SELECT totp_secret FROM users WHERE id = $1 AND totp_enabled")
                .bind(user.as_uuid())
                .fetch_optional(&self.pool)
                .await
                .context("read an account's TOTP secret")?;
        secret.flatten().map(secret_of).transpose()
    }

    async fn start_enrollment(&self, user: UserId, secret: &TotpSecret) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO pending_totp_enrollments (user_id, secret) VALUES ($1, $2) \
             ON CONFLICT (user_id) DO UPDATE SET secret = EXCLUDED.secret, created_at = now()",
        )
        .bind(user.as_uuid())
        .bind(secret.as_bytes())
        .execute(&self.pool)
        .await
        .context("keep a TOTP enrollment")?;
        Ok(())
    }

    async fn pending(&self, user: UserId) -> Result<Option<TotpSecret>, AuthError> {
        let secret: Option<Vec<u8>> =
            sqlx::query_scalar("SELECT secret FROM pending_totp_enrollments WHERE user_id = $1")
                .bind(user.as_uuid())
                .fetch_optional(&self.pool)
                .await
                .context("read a TOTP enrollment")?;
        secret.map(secret_of).transpose()
    }

    async fn enable(
        &self,
        user: UserId,
        secret: &TotpSecret,
        step: i64,
    ) -> Result<Vec<String>, AuthError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .context("begin turning a second factor on")?;
        sqlx::query(
            "UPDATE users SET totp_secret = $2, totp_enabled = TRUE, totp_last_step = $3, \
                              updated_at = now() \
             WHERE id = $1",
        )
        .bind(user.as_uuid())
        .bind(secret.as_bytes())
        .bind(step)
        .execute(&mut *tx)
        .await
        .context("turn a second factor on")?;
        sqlx::query("DELETE FROM pending_totp_enrollments WHERE user_id = $1")
            .bind(user.as_uuid())
            .execute(&mut *tx)
            .await
            .context("forget a TOTP enrollment")?;
        let codes = self.store_recovery_codes(&mut tx, user).await?;
        tx.commit().await.context("commit a second factor")?;
        Ok(codes)
    }

    async fn disable(&self, user: UserId) -> Result<(), AuthError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .context("begin turning a second factor off")?;
        sqlx::query(
            "UPDATE users SET totp_secret = NULL, totp_enabled = FALSE, totp_last_step = NULL, \
                              updated_at = now() \
             WHERE id = $1",
        )
        .bind(user.as_uuid())
        .execute(&mut *tx)
        .await
        .context("turn a second factor off")?;
        sqlx::query("DELETE FROM recovery_codes WHERE user_id = $1")
            .bind(user.as_uuid())
            .execute(&mut *tx)
            .await
            .context("delete the recovery codes")?;
        sqlx::query("DELETE FROM pending_totp_enrollments WHERE user_id = $1")
            .bind(user.as_uuid())
            .execute(&mut *tx)
            .await
            .context("forget a TOTP enrollment")?;
        tx.commit()
            .await
            .context("commit turning a second factor off")?;
        Ok(())
    }

    async fn replace_recovery_codes(&self, user: UserId) -> Result<Vec<String>, AuthError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .context("begin replacing recovery codes")?;
        let codes = self.store_recovery_codes(&mut tx, user).await?;
        tx.commit().await.context("commit the recovery codes")?;
        Ok(codes)
    }

    async fn use_step(&self, user: UserId, step: i64) -> Result<bool, AuthError> {
        let used = sqlx::query(
            "UPDATE users SET totp_last_step = $2 \
             WHERE id = $1 AND totp_enabled \
               AND (totp_last_step IS NULL OR totp_last_step < $2)",
        )
        .bind(user.as_uuid())
        .bind(step)
        .execute(&self.pool)
        .await
        .context("use a TOTP step")?
        .rows_affected();
        Ok(used == 1)
    }

    async fn use_recovery_code(&self, user: UserId, submitted: &str) -> Result<bool, AuthError> {
        // Matched by its HMAC: without the pepper, the hashes tell nothing of the codes.
        let used = sqlx::query(
            "UPDATE recovery_codes SET consumed_at = now() \
             WHERE id = (SELECT id FROM recovery_codes \
                         WHERE user_id = $1 AND code_hash = $2 AND consumed_at IS NULL \
                         LIMIT 1 FOR UPDATE SKIP LOCKED)",
        )
        .bind(user.as_uuid())
        .bind(self.hash(submitted))
        .execute(&self.pool)
        .await
        .context("use a recovery code")?
        .rows_affected();
        Ok(used == 1)
    }
}

#[cfg(test)]
mod tests;
