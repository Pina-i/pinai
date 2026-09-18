#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("S3 error: {0}")]
    S3(String),

    #[error("Bucket initialization failed: {0}")]
    BucketInit(String),

    #[error("Invalid content type: {0}")]
    InvalidContentType(String),

    #[error("Upload failed: {0}")]
    UploadFailed(String),

    #[error("Delete failed: {0}")]
    DeleteFailed(String),
}
