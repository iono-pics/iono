mod s3;

pub use s3::S3Storage;

use crate::config::Config;
use crate::error::AppResult;
use async_trait::async_trait;
use bytes::Bytes;
use futures_util::stream::BoxStream;
use std::sync::Arc;

pub struct StoredObject {
    pub stream: BoxStream<'static, std::io::Result<Bytes>>,
    pub content_length: Option<u64>,
    pub content_range: Option<String>,
}

#[async_trait]
pub trait Storage: Send + Sync {
    async fn save(&self, key: &str, data: &[u8], content_type: &str) -> AppResult<()>;
    async fn get(&self, key: &str, range: Option<&str>) -> AppResult<StoredObject>;
    async fn delete(&self, key: &str) -> AppResult<()>;
    async fn delete_many(&self, keys: &[String]) -> AppResult<Vec<String>>;
}

pub async fn build(config: &Config) -> AppResult<Arc<dyn Storage>> {
    Ok(Arc::new(S3Storage::new(config).await?))
}
