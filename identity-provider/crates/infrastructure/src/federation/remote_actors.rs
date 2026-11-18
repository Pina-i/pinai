use anyhow::Context;
use domain::ValidationError;
use domain::identity::{ActorUri, FederatedAddress, RemoteActor, RemoteActors, RemoteActorsError};
use domain::profile::{Pronouns, PublicProfile};
use federation_transport::{TransportError, UrlPolicy, fetch_remote_actor, resolve_remote_actor};
use sqlx::PgPool;

/// Remote accounts: resolved over WebFinger, remembered in `remote_actors`.
pub struct FederatedRemoteActors {
    pool: PgPool,
    scheme: String,
    policy: UrlPolicy,
}

impl FederatedRemoteActors {
    /// `scheme` is the one peers are reached over — this instance's own.
    pub fn new(pool: PgPool, scheme: String, policy: UrlPolicy) -> Self {
        Self {
            pool,
            scheme,
            policy,
        }
    }

    // A fetch that brings no inbox, name or avatar keeps the cached one: a peer that is down, or
    // a document this instance won't take, must not erase what was read before. A name, an
    // avatar or a bio outside the peer profile limits counts as none. The pronouns and bio of a
    // document that was read are taken as it gives them, cleared when it has none; with no
    // document, the cached ones stay, and so does `fetched_at` — the epoch for an actor never
    // read —, so the profile card asks again rather than holding it fresh for a day.
    async fn remember(
        &self,
        actor: &ActorUri,
        inbox: Option<&str>,
        shown: Option<Shown>,
    ) -> Result<RemoteActor, RemoteActorsError> {
        let read = shown.is_some();
        let shown = shown.unwrap_or_default();
        let profile = PublicProfile {
            actor: actor.clone(),
            display_name: shown.display_name,
            avatar_url: shown.avatar_url,
            pronouns: shown.pronouns.and_then(|p| Pronouns::parse(&p).ok()),
            bio: shown.bio,
        }
        .within_limits();
        let row: RemoteActorRow = sqlx::query_as(
            "INSERT INTO remote_actors \
                (actor_uri, inbox_url, instance, display_name, avatar_url, pronouns, bio, \
                 fetched_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, \
                     CASE WHEN $8 THEN now() ELSE 'epoch'::timestamptz END) \
             ON CONFLICT (actor_uri) DO UPDATE SET \
                inbox_url    = COALESCE(EXCLUDED.inbox_url, remote_actors.inbox_url), \
                display_name = COALESCE(EXCLUDED.display_name, remote_actors.display_name), \
                avatar_url   = COALESCE(EXCLUDED.avatar_url, remote_actors.avatar_url), \
                pronouns     = CASE WHEN $8 THEN EXCLUDED.pronouns ELSE remote_actors.pronouns END, \
                bio          = CASE WHEN $8 THEN EXCLUDED.bio ELSE remote_actors.bio END, \
                fetched_at   = CASE WHEN $8 THEN now() ELSE remote_actors.fetched_at END, \
                updated_at   = now() \
             RETURNING actor_uri, inbox_url, display_name, avatar_url",
        )
        .bind(actor.as_str())
        .bind(inbox)
        .bind(actor.domain().to_string())
        .bind(profile.display_name)
        .bind(profile.avatar_url)
        .bind(profile.pronouns.map(Pronouns::as_str))
        .bind(profile.bio)
        .bind(read)
        .fetch_one(&self.pool)
        .await
        .context("remember a remote actor")?;
        Ok(row.try_into()?)
    }

    /// The actor's inbox and what its document shows, if it can be read, names the actor and
    /// keeps within the limits.
    async fn read(&self, actor: &ActorUri) -> Option<(url::Url, Shown)> {
        let found = fetch_remote_actor(actor.as_str(), self.policy)
            .await
            .map_err(|e| e.to_string())
            .and_then(|found| kept(found).map_err(|e| e.to_string()))
            .inspect_err(
                |e| tracing::debug!(error = %e, %actor, "remote actor document unavailable"),
            )
            .ok()?;
        Some(found)
    }
}

/// What an actor's document shows of its account.
#[derive(Default)]
struct Shown {
    display_name: Option<String>,
    avatar_url: Option<String>,
    pronouns: Option<String>,
    bio: Option<String>,
}

/// The inbox and what is shown of an actor its instance described, the inbox as it is stored.
fn kept(found: federation_transport::RemoteActor) -> Result<(url::Url, Shown), ValidationError> {
    let inbox = RemoteActor::parse_inbox(found.inbox.as_str())?;
    let shown = Shown {
        display_name: found.display_name,
        avatar_url: found.avatar_url,
        pronouns: found.pronouns,
        bio: found.bio,
    };
    Ok((inbox, shown))
}

/// What a peer answered that this instance won't store: no instance would answer it.
fn unanswerable(e: ValidationError) -> RemoteActorsError {
    RemoteActorsError::Unavailable(format!("the peer answered no valid {e}"))
}

#[derive(sqlx::FromRow)]
pub(crate) struct RemoteActorRow {
    actor_uri: String,
    inbox_url: Option<String>,
    display_name: Option<String>,
    avatar_url: Option<String>,
}

impl TryFrom<RemoteActorRow> for RemoteActor {
    type Error = anyhow::Error;

    fn try_from(row: RemoteActorRow) -> Result<Self, Self::Error> {
        let actor_uri = ActorUri::parse(&row.actor_uri).context("remote_actors.actor_uri")?;
        let inbox = row
            .inbox_url
            .unwrap_or_else(|| format!("{}/inbox", actor_uri.as_str()));
        Ok(RemoteActor {
            inbox: url::Url::parse(&inbox).context("remote_actors.inbox_url")?,
            actor_uri,
            display_name: row.display_name,
            avatar_url: row.avatar_url,
        })
    }
}

fn refusal(error: TransportError) -> RemoteActorsError {
    match error {
        TransportError::NotFound(_) => RemoteActorsError::NotFound,
        TransportError::Denied(reason) | TransportError::BadRequest(reason) => {
            RemoteActorsError::Refused(reason)
        }
        TransportError::Upstream(reason) => RemoteActorsError::Unavailable(reason),
    }
}

#[async_trait::async_trait]
impl RemoteActors for FederatedRemoteActors {
    async fn resolve(&self, address: &FederatedAddress) -> Result<RemoteActor, RemoteActorsError> {
        let found = resolve_remote_actor(
            address.user(),
            address.domain().as_str(),
            &self.scheme,
            self.policy,
        )
        .await
        .map_err(refusal)?;
        let actor = ActorUri::parse(found.actor_url.as_str()).map_err(unanswerable)?;
        let (inbox, shown) = kept(found).map_err(unanswerable)?;
        self.remember(&actor, Some(inbox.as_str()), Some(shown))
            .await
    }

    async fn find(&self, uri: &ActorUri) -> Result<Option<RemoteActor>, RemoteActorsError> {
        let row: Option<RemoteActorRow> = sqlx::query_as(
            "SELECT actor_uri, inbox_url, display_name, avatar_url \
             FROM remote_actors WHERE actor_uri = $1",
        )
        .bind(uri.as_str())
        .fetch_optional(&self.pool)
        .await
        .context("find a remote actor")?;
        Ok(row.map(RemoteActor::try_from).transpose()?)
    }

    async fn discover(&self, uri: &ActorUri) -> Result<RemoteActor, RemoteActorsError> {
        if uri.federated_address().is_none() {
            return Err(RemoteActorsError::NotFound);
        }
        let (inbox, shown) = self.read(uri).await.unzip();
        self.remember(uri, inbox.as_ref().map(url::Url::as_str), shown)
            .await
    }
}

#[cfg(test)]
mod tests;
