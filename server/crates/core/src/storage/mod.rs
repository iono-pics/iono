mod s3;

pub use s3::S3Storage;

use crate::config::Config;
use crate::error::AppResult;
use async_trait::async_trait;
use std::sync::Arc;

#[async_trait]
pub trait Storage: Send + Sync {
    async fn save(&self, key: &str, data: &[u8], content_type: &str) -> AppResult<()>;
    async fn public_url(&self, key: &str, content_type: &str) -> AppResult<String>;
}

pub async fn build(config: &Config) -> AppResult<Arc<dyn Storage>> {
    Ok(Arc::new(S3Storage::new(config).await?))
}
