use std::sync::Arc;

use domain::DeviceId;
use domain::auth::Sessions;
use domain::e2ee::{KeyDirectoryError, PushRegistration, PushRegistrations, PushWrite};
use domain::identity::Bearer;
use time::OffsetDateTime;

use crate::auth::calling_session;

/// `PUT /api/keys/devices/{id}/push`: where the instance sends the device's push notices, from that
/// device's own session — which sets it again at each start, as the relay may hand it another
/// token.
pub struct RegisterPush {
    pushes: Arc<dyn PushRegistrations>,
    sessions: Arc<dyn Sessions>,
}

impl RegisterPush {
    pub fn new(pushes: Arc<dyn PushRegistrations>, sessions: Arc<dyn Sessions>) -> Self {
        Self { pushes, sessions }
    }

    pub async fn execute(
        &self,
        bearer: &Bearer,
        device: DeviceId,
        registration: &PushRegistration,
        now: OffsetDateTime,
    ) -> Result<(), KeyDirectoryError> {
        let named = named_device(&*self.sessions, bearer).await?;
        done(
            self.pushes
                .set(bearer.user, device, named, registration, now)
                .await?,
        )
    }
}

/// `DELETE /api/keys/devices/{id}/push`: the device is sent nothing more — at its sign-out, or once
/// its user turned notices off.
pub struct UnregisterPush {
    pushes: Arc<dyn PushRegistrations>,
    sessions: Arc<dyn Sessions>,
}

impl UnregisterPush {
    pub fn new(pushes: Arc<dyn PushRegistrations>, sessions: Arc<dyn Sessions>) -> Self {
        Self { pushes, sessions }
    }

    pub async fn execute(
        &self,
        bearer: &Bearer,
        device: DeviceId,
    ) -> Result<(), KeyDirectoryError> {
        let named = named_device(&*self.sessions, bearer).await?;
        done(self.pushes.remove(bearer.user, device, named).await?)
    }
}

async fn named_device(
    sessions: &dyn Sessions,
    bearer: &Bearer,
) -> Result<Option<DeviceId>, KeyDirectoryError> {
    Ok(calling_session(sessions, bearer)
        .await
        .map_err(|e| KeyDirectoryError::Unexpected(e.into()))?
        .device)
}

fn done(write: PushWrite) -> Result<(), KeyDirectoryError> {
    match write {
        PushWrite::Done => Ok(()),
        PushWrite::Refused(refusal) => Err(refusal),
    }
}
