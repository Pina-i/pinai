use anyhow::Context;
use domain::identity::{ActorUri, FederatedAddress, RemoteActor, RemoteActors, RemoteActorsError};
use domain::profile::PublicProfile;
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
    // or an actor first seen through a Follow, must not erase what WebFinger resolved. A name or
    // avatar outside the peer profile limits counts as none.
    async fn remember(
        &self,
        actor: &ActorUri,
        inbox: Option<&str>,
        display_name: Option<String>,
        avatar_url: Option<String>,
    ) -> Result<RemoteActor, RemoteActorsError> {
        let shown = PublicProfile {
            actor: actor.clone(),
            display_name,
            avatar_url,
        }
        .within_limits();
        let row: RemoteActorRow = sqlx::query_as(
            "INSERT INTO remote_actors (actor_uri, inbox_url, instance, display_name, avatar_url) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (actor_uri) DO UPDATE SET \
                inbox_url    = COALESCE(EXCLUDED.inbox_url, remote_actors.inbox_url), \
                display_name = COALESCE(EXCLUDED.display_name, remote_actors.display_name), \
                avatar_url   = COALESCE(EXCLUDED.avatar_url, remote_actors.avatar_url), \
                fetched_at   = now(), \
                updated_at   = now() \
             RETURNING actor_uri, inbox_url, display_name, avatar_url",
        )
        .bind(actor.as_str())
        .bind(inbox)
        .bind(actor.domain().to_string())
        .bind(shown.display_name)
        .bind(shown.avatar_url)
        .fetch_one(&self.pool)
        .await
        .context("remember a remote actor")?;
        Ok(row.try_into()?)
    }

    /// The name and avatar the actor's document gives, if it can be read.
    async fn shown_by(&self, actor: &ActorUri) -> (Option<String>, Option<String>) {
        let Ok(document) =
            get_json_screened(actor.as_str(), "application/activity+json", self.policy)
                .await
                .inspect_err(
                    |e| tracing::debug!(error = %e, %actor, "remote actor document unavailable"),
                )
        else {
            return (None, None);
        };
        let Ok(actor) = serde_json::from_value::<activitypub::Actor>(document) else {
            return (None, None);
        };
        let avatar_url = actor.icon_url().map(str::to_owned);
        (Some(actor.name).filter(|name| !name.is_empty()), avatar_url)
    }
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
        let actor = ActorUri::parse(&found.actor_url).context("the peer's actor id")?;
        self.remember(
            &actor,
            Some(&found.inbox),
            found.display_name,
            found.avatar_url,
        )
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
        let (display_name, avatar_url) = self.shown_by(uri).await;
        self.remember(uri, None, display_name, avatar_url).await
    }
}

#[cfg(test)]
mod tests;
