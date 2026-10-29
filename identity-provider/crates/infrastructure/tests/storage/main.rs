//! Object-store adapter tests against a real RustFS, the one `make test-integration` starts.

use aws_credential_types::Credentials;
use aws_sdk_s3::config::Region;
use aws_sdk_s3::error::ProvideErrorMetadata;
use bytes::Bytes;
use domain::profile::testing::contract;
use infrastructure::storage::{S3AvatarStore, StorageClient, StorageConfig};

const ACCESS_KEY: &str = "test";
const SECRET_KEY: &str = "test-secret";

fn endpoint() -> String {
    std::env::var("TEST_STORAGE_URL").unwrap_or_else(|_| "http://localhost:59000".into())
}

/// Buckets of its own, so that no two tests share one.
fn config() -> StorageConfig {
    let suffix = uuid::Uuid::new_v4().simple();
    StorageConfig {
        endpoint: endpoint(),
        access_key: ACCESS_KEY.into(),
        secret_key: SECRET_KEY.into(),
        bucket_avatars: format!("avatars-{suffix}"),
        bucket_attachments: format!("attachments-{suffix}"),
    }
}

async fn started(config: &StorageConfig) -> StorageClient {
    let client = StorageClient::new(config).await.unwrap();
    client
        .ensure_buckets()
        .await
        .expect("the test RustFS — `make test-integration` starts it");
    client
}

async fn avatars() -> S3AvatarStore {
    S3AvatarStore::new(Some(started(&config()).await))
}

/// The server as an operator reaches it, past the adapter.
fn s3() -> aws_sdk_s3::Client {
    let config = aws_sdk_s3::config::Builder::new()
        .behavior_version_latest()
        .endpoint_url(endpoint())
        .region(Region::new("us-east-1"))
        .credentials_provider(Credentials::new(ACCESS_KEY, SECRET_KEY, None, None, "test"))
        .force_path_style(true)
        .build();
    aws_sdk_s3::Client::from_conf(config)
}

#[tokio::test]
async fn a_stored_avatar_opens_with_its_bytes() {
    contract::a_stored_avatar_opens_with_its_bytes(&avatars().await).await;
}

#[tokio::test]
async fn an_image_never_stored_does_not_open() {
    contract::an_image_never_stored_does_not_open(&avatars().await).await;
}

#[tokio::test]
async fn a_removed_image_no_longer_opens() {
    contract::a_removed_image_no_longer_opens(&avatars().await).await;
}

#[tokio::test]
async fn the_avatars_bucket_is_private_after_startup_even_once_public_read() {
    let config = config();
    let bucket = &config.bucket_avatars;
    let s3 = s3();
    s3.create_bucket().bucket(bucket).send().await.unwrap();
    let public_read = serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": "*",
            "Action": ["s3:GetObject"],
            "Resource": [format!("arn:aws:s3:::{bucket}/*")]
        }]
    });
    s3.put_bucket_policy()
        .bucket(bucket)
        .policy(public_read.to_string())
        .send()
        .await
        .unwrap();
    s3.put_object()
        .bucket(bucket)
        .key("old.png")
        .body(Bytes::from_static(b"\x89PNG").into())
        .send()
        .await
        .unwrap();
    let object = format!("{}/{bucket}/old.png", endpoint());
    let before = reqwest::get(&object).await.unwrap().status();

    let client = started(&config).await;
    // Again, on a bucket without a policy: no error.
    client.ensure_buckets().await.unwrap();

    assert_eq!(before, reqwest::StatusCode::OK, "public-read to begin with");
    let policy = s3.get_bucket_policy().bucket(bucket).send().await;
    let refused = policy.expect_err("no policy left");
    assert_eq!(
        refused.as_service_error().and_then(|e| e.code()),
        Some("NoSuchBucketPolicy")
    );
    let after = reqwest::get(&object).await.unwrap().status();
    assert_eq!(after, reqwest::StatusCode::FORBIDDEN);
}
