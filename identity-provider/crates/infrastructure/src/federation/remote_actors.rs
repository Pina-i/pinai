use anyhow::Context;
use domain::identity::{ActorUri, FederatedAddress, RemoteActor, RemoteActors, RemoteActorsError};
use federation_transport::http::get_json_screened;
use federation_transport::{TransportError, UrlPolicy, resolve_remote_actor};
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

    // A fetch that brings no inbox, name or avatar keeps the cached one: a peer that is down,
    // or an actor first seen through a Follow, must not erase what WebFinger resolved.
    async fn remember(
        &self,
        actor: &ActorUri,
        inbox: Option<&str>,
        display_name: Option<&str>,
    ) -> Result<RemoteActor, RemoteActorsError> {
        let row: RemoteActorRow = sqlx::query_as(
            "INSERT INTO remote_actors (actor_uri, inbox_url, instance, display_name) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (actor_uri) DO UPDATE SET \
                inbox_url    = COALESCE(EXCLUDED.inbox_url, remote_actors.inbox_url), \
                display_name = COALESCE(EXCLUDED.display_name, remote_actors.display_name), \
                fetched_at   = now(), \
                updated_at   = now() \
             RETURNING actor_uri, inbox_url, display_name, avatar_url",
        )
        .bind(actor.as_str())
        .bind(inbox)
        .bind(actor.domain().to_string())
        .bind(display_name)
        .fetch_one(&self.pool)
        .await
        .context("remember a remote actor")?;
        Ok(row.try_into()?)
    }

    async fn display_name_of(&self, actor: &ActorUri) -> Option<String> {
        let document = get_json_screened(actor.as_str(), "application/activity+json", self.policy)
            .await
            .inspect_err(
                |e| tracing::debug!(error = %e, %actor, "remote actor document unavailable"),
            )
            .ok()?;
        let actor: activitypub::Actor = serde_json::from_value(document).ok()?;
        Some(actor.name).filter(|name| !name.is_empty())
    }
}

#[derive(sqlx::FromRow)]
struct RemoteActorRow {
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
        TransportError::Upstream(reason) => RemoteActorsError::Unexpected(anyhow::anyhow!(reason)),
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
        let actor = ActorUri::parse(&found.actor_url).context("the peer's actor id")?;
        self.remember(&actor, Some(&found.inbox), found.display_name.as_deref())
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
        let display_name = self.display_name_of(uri).await;
        self.remember(uri, None, display_name.as_deref()).await
    }
}
