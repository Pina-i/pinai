//! The history passphrase shared between the account's devices — see
//! identity-provider/specs/e2ee.md § 3.11.

use std::sync::Arc;

use application::e2ee::{LoadKeyShare, ShareHistoryKey};
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use domain::e2ee::{
    Ed25519Signature, HistoryGeneration, KeyShare, SealedShare, ShareCiphertext, ShareEnc,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::ApiError;
use crate::auth::SignedIn;
use crate::e2ee::base64_field;

#[derive(Deserialize)]
pub struct ShareBody {
    recipient_device_id: Uuid,
    generation: i64,
    /// Standard base64 of the 32-byte HPKE encapsulated key.
    enc: String,
    /// Standard base64 of the sealed passphrase, 1 to 1024 bytes.
    ciphertext: String,
    /// Standard base64 of the sender's root key's 64-byte signature over the share's bytes.
    signature: String,
}

#[derive(Serialize)]
pub struct HeldShareBody {
    sender_device_id: Uuid,
    generation: i32,
    enc: String,
    ciphertext: String,
    signature: String,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
}

impl TryFrom<&ShareBody> for SealedShare {
    type Error = ApiError;

    fn try_from(body: &ShareBody) -> Result<Self, Self::Error> {
        Ok(SealedShare {
            enc: base64_field("enc", &body.enc, ShareEnc::parse)?,
            ciphertext: base64_field("ciphertext", &body.ciphertext, |bytes| {
                ShareCiphertext::parse(bytes.to_vec())
            })?,
            signature: base64_field("signature", &body.signature, |bytes| {
                Ed25519Signature::parse("signature", bytes)
            })?,
        })
    }
}

impl From<KeyShare> for HeldShareBody {
    fn from(share: KeyShare) -> Self {
        Self {
            sender_device_id: share.sender.as_uuid(),
            generation: share.generation.value(),
            enc: B64.encode(share.sealed.enc.as_bytes()),
            ciphertext: B64.encode(share.sealed.ciphertext.as_bytes()),
            signature: B64.encode(share.sealed.signature.as_bytes()),
            created_at: share.created_at,
        }
    }
}

/// `POST /api/history/key-shares`
pub async fn share(
    State(share): State<Arc<ShareHistoryKey>>,
    SignedIn(bearer): SignedIn,
    Json(body): Json<ShareBody>,
) -> Result<StatusCode, ApiError> {
    let generation = HistoryGeneration::parse(body.generation)?;
    let sealed = SealedShare::try_from(&body)?;
    share
        .execute(
            &bearer,
            body.recipient_device_id.into(),
            generation,
            sealed,
            OffsetDateTime::now_utc(),
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /api/history/key-shares`
pub async fn held(
    State(load): State<Arc<LoadKeyShare>>,
    SignedIn(bearer): SignedIn,
) -> Result<Json<HeldShareBody>, ApiError> {
    Ok(Json(load.execute(&bearer).await?.into()))
}

#[cfg(test)]
mod tests;
