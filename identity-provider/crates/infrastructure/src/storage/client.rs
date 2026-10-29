use aws_credential_types::Credentials;
use aws_sdk_s3::error::{DisplayErrorContext, ProvideErrorMetadata};
use aws_sdk_s3::operation::get_object::GetObjectOutput;
use aws_sdk_s3::{Client, config::Region, primitives::ByteStream as S3Body};
use domain::messaging::ByteStream;
use tokio_util::io::ReaderStream;

use super::StorageError;

/// Configuration needed to build a [`StorageClient`].
pub struct StorageConfig {
    pub endpoint: String,
    pub access_key: String,
    pub secret_key: String,
    pub bucket_avatars: String,
    pub bucket_attachments: String,
}

/// Thin wrapper around an S3 client scoped to the IdP's buckets, both private: every byte a
/// browser or a peer sees goes through the IdP.
#[derive(Clone)]
pub struct StorageClient {
    client: Client,
    bucket_avatars: String,
    bucket_attachments: String,
}

impl StorageClient {
    /// Build an S3 client configured for a local S3-compatible server (RustFS / MinIO).
    pub async fn new(cfg: &StorageConfig) -> Result<Self, StorageError> {
        let creds = Credentials::new(
            &cfg.access_key,
            &cfg.secret_key,
            None, // session token
            None, // expiry
            "env",
        );

        let s3_config = aws_sdk_s3::config::Builder::new()
            .behavior_version_latest()
            .endpoint_url(&cfg.endpoint)
            .region(Region::new("us-east-1"))
            .credentials_provider(creds)
            .force_path_style(true) // required for MinIO / RustFS
            .build();

        let client = Client::from_conf(s3_config);

        Ok(Self {
            client,
            bucket_avatars: cfg.bucket_avatars.clone(),
            bucket_attachments: cfg.bucket_attachments.clone(),
        })
    }

    /// Ensure both buckets exist, both private: any policy on the avatars one is removed. Call
    /// once at startup.
    pub async fn ensure_buckets(&self) -> Result<(), StorageError> {
        self.ensure_bucket(&self.bucket_avatars).await?;
        self.remove_bucket_policy(&self.bucket_avatars).await?;
        self.ensure_bucket(&self.bucket_attachments).await?;
        Ok(())
    }

    /// Upload an avatar image under `key`, its file name.
    pub async fn upload_avatar(
        &self,
        key: &str,
        data: Vec<u8>,
        content_type: &str,
    ) -> Result<(), StorageError> {
        self.client
            .put_object()
            .bucket(&self.bucket_avatars)
            .key(key)
            .body(S3Body::from(data))
            .content_type(content_type)
            .send()
            .await
            .map_err(|e| StorageError::UploadFailed(DisplayErrorContext(&e).to_string()))?;

        tracing::info!(key = %key, "avatar uploaded");
        Ok(())
    }

    /// Stream an avatar's bytes, as [`Self::fetch_attachment_stream`] does; `None` when no
    /// object has that key.
    pub async fn fetch_avatar_stream(&self, key: &str) -> Result<Option<ByteStream>, StorageError> {
        let resp = self
            .client
            .get_object()
            .bucket(&self.bucket_avatars)
            .key(key)
            .send()
            .await;
        match resp {
            Ok(resp) => Ok(Some(streamed(resp))),
            Err(e) if e.as_service_error().is_some_and(|e| e.is_no_such_key()) => Ok(None),
            Err(e) => Err(StorageError::S3(DisplayErrorContext(&e).to_string())),
        }
    }

    /// Delete an avatar object. Idempotent: S3 answers a missing key as deleted.
    pub async fn delete_avatar(&self, key: &str) -> Result<(), StorageError> {
        self.client
            .delete_object()
            .bucket(&self.bucket_avatars)
            .key(key)
            .send()
            .await
            .map_err(|e| StorageError::DeleteFailed(DisplayErrorContext(&e).to_string()))?;
        Ok(())
    }

    // ── Attachments ─────────────────────────────────────────────────────

    /// Upload an attachment to the (private) attachments bucket. The caller
    /// chooses `storage_key` — typically the attachment row's UUID rendered
    /// as a string. Bytes are stored with their declared `content_type`; the
    /// IdP's `/blob` handler re-applies it on the way out when streaming.
    pub async fn upload_attachment(
        &self,
        storage_key: &str,
        data: Vec<u8>,
        content_type: &str,
    ) -> Result<(), StorageError> {
        self.client
            .put_object()
            .bucket(&self.bucket_attachments)
            .key(storage_key)
            .body(S3Body::from(data))
            .content_type(content_type)
            .send()
            .await
            .map_err(|e| StorageError::UploadFailed(DisplayErrorContext(&e).to_string()))?;

        tracing::info!(key = %storage_key, "attachment uploaded");
        Ok(())
    }

    /// Delete an attachment object. Idempotent — a missing key returns Ok(()).
    pub async fn delete_attachment(&self, storage_key: &str) -> Result<(), StorageError> {
        let _ = self
            .client
            .delete_object()
            .bucket(&self.bucket_attachments)
            .key(storage_key)
            .send()
            .await;

        tracing::info!(key = %storage_key, "attachment deleted");
        Ok(())
    }

    /// Stream an attachment's bytes back from the object store, alongside the
    /// content-length the store reports. Used by the IdP's `/blob` handler to
    /// proxy bytes to the browser — the object store stays on the private
    /// network, the browser only ever talks to the IdP. Authorization is
    /// enforced upstream by the IdP's HMAC token.
    pub async fn fetch_attachment_stream(
        &self,
        storage_key: &str,
    ) -> Result<ByteStream, StorageError> {
        let resp = self
            .client
            .get_object()
            .bucket(&self.bucket_attachments)
            .key(storage_key)
            .send()
            .await
            .map_err(|e| StorageError::S3(DisplayErrorContext(&e).to_string()))?;

        Ok(streamed(resp))
    }

    // ── Internal helpers ────────────────────────────────────────────────

    async fn ensure_bucket(&self, name: &str) -> Result<(), StorageError> {
        let exists = self.client.head_bucket().bucket(name).send().await;

        if exists.is_err() {
            tracing::info!(bucket = %name, "creating bucket");
            self.client
                .create_bucket()
                .bucket(name)
                .send()
                .await
                .map_err(|e| {
                    StorageError::BucketInit(format!("{name}: {}", DisplayErrorContext(&e)))
                })?;
        }
        Ok(())
    }

    /// A bucket without a policy is no error: RustFS and S3 answer it as removed, another store
    /// may say `NoSuchBucketPolicy`.
    async fn remove_bucket_policy(&self, bucket: &str) -> Result<(), StorageError> {
        match self
            .client
            .delete_bucket_policy()
            .bucket(bucket)
            .send()
            .await
        {
            Ok(_) => Ok(()),
            Err(e) if e.code() == Some("NoSuchBucketPolicy") => Ok(()),
            Err(e) => Err(StorageError::BucketInit(format!(
                "failed to remove the policy of {bucket}: {}",
                DisplayErrorContext(&e)
            ))),
        }
    }
}

/// S3 body → AsyncRead → a stream of chunks, so axum can adopt it as a response body without
/// buffering the full payload in RAM.
fn streamed(resp: GetObjectOutput) -> ByteStream {
    ByteStream {
        length: resp.content_length().and_then(|n| u64::try_from(n).ok()),
        chunks: Box::pin(ReaderStream::new(resp.body.into_async_read())),
    }
}
