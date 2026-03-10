use aws_credential_types::Credentials;
use aws_sdk_s3::{config::Region, primitives::ByteStream, Client};
use uuid::Uuid;

use crate::StorageError;

/// Configuration needed to build a [`StorageClient`].
pub struct StorageConfig {
    pub endpoint: String,
    pub access_key: String,
    pub secret_key: String,
    pub bucket_avatars: String,
    pub bucket_attachments: String,
    /// The publicly-reachable base URL of the S3 server (used to build avatar URLs).
    pub public_url: String,
}

/// Thin wrapper around an S3 client scoped to the IdP's buckets.
#[derive(Clone)]
pub struct StorageClient {
    client: Client,
    bucket_avatars: String,
    bucket_attachments: String,
    public_url: String,
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
            public_url: cfg.public_url.trim_end_matches('/').to_string(),
        })
    }

    /// Ensure both buckets exist. Call once at startup.
    pub async fn ensure_buckets(&self) -> Result<(), StorageError> {
        self.ensure_bucket(&self.bucket_avatars).await?;
        self.set_bucket_public_read(&self.bucket_avatars).await?;
        self.ensure_bucket(&self.bucket_attachments).await?;
        Ok(())
    }

    /// Upload an avatar image. Returns the public URL.
    ///
    /// Object key: `{user_id}.{ext}` (e.g. `550e8400-…-007f.jpg`).
    pub async fn upload_avatar(
        &self,
        user_id: Uuid,
        data: Vec<u8>,
        content_type: &str,
    ) -> Result<String, StorageError> {
        let ext = extension_from_content_type(content_type)?;
        let key = format!("{user_id}.{ext}");

        self.client
            .put_object()
            .bucket(&self.bucket_avatars)
            .key(&key)
            .body(ByteStream::from(data))
            .content_type(content_type)
            .send()
            .await
            .map_err(|e| StorageError::UploadFailed(e.to_string()))?;

        tracing::info!(user_id = %user_id, key = %key, "avatar uploaded");

        let url = format!("{}/{}/{}", self.public_url, self.bucket_avatars, key);
        Ok(url)
    }

    /// Delete avatar(s) for a user. Tries all known extensions (idempotent).
    pub async fn delete_avatar(&self, user_id: Uuid) -> Result<(), StorageError> {
        for ext in ["jpg", "png", "webp", "gif"] {
            let key = format!("{user_id}.{ext}");
            let _ = self
                .client
                .delete_object()
                .bucket(&self.bucket_avatars)
                .key(&key)
                .send()
                .await;
        }
        tracing::info!(user_id = %user_id, "avatar deleted");
        Ok(())
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
                .map_err(|e| StorageError::BucketInit(format!("{name}: {e}")))?;
        }
        Ok(())
    }

    async fn set_bucket_public_read(&self, bucket: &str) -> Result<(), StorageError> {
        let policy = serde_json::json!({
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "PublicRead",
                "Effect": "Allow",
                "Principal": "*",
                "Action": ["s3:GetObject"],
                "Resource": [format!("arn:aws:s3:::{bucket}/*")]
            }]
        });

        self.client
            .put_bucket_policy()
            .bucket(bucket)
            .policy(policy.to_string())
            .send()
            .await
            .map_err(|e| {
                StorageError::BucketInit(format!(
                    "failed to set public-read policy on {bucket}: {e}"
                ))
            })?;

        Ok(())
    }
}

fn extension_from_content_type(ct: &str) -> Result<&'static str, StorageError> {
    match ct {
        "image/jpeg" => Ok("jpg"),
        "image/png" => Ok("png"),
        "image/webp" => Ok("webp"),
        "image/gif" => Ok("gif"),
        _ => Err(StorageError::InvalidContentType(format!(
            "unsupported: {ct}; expected image/jpeg, image/png, image/webp, or image/gif"
        ))),
    }
}
