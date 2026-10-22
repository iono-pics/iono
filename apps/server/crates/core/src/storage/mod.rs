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
    async fn save_stream(
        &self,
        key: &str,
        content_type: &str,
        stream: BoxStream<'static, AppResult<Bytes>>,
    ) -> AppResult<()>;
    async fn begin_multipart(&self, key: &str, content_type: &str) -> AppResult<String>;
    /// returns the part's etag, which complete_multipart needs back
    async fn put_part(
        &self,
        key: &str,
        upload_id: &str,
        part_number: i32,
        body: Vec<u8>,
    ) -> AppResult<String>;
    async fn complete_multipart(
        &self,
        key: &str,
        upload_id: &str,
        parts: Vec<(i32, String)>,
    ) -> AppResult<()>;
    async fn abort_multipart(&self, key: &str, upload_id: &str) -> AppResult<()>;
    async fn get(&self, key: &str, range: Option<&str>) -> AppResult<StoredObject>;
    async fn delete(&self, key: &str) -> AppResult<()>;
    async fn delete_many(&self, keys: &[String]) -> AppResult<Vec<String>>;
}

pub async fn build(config: &Config) -> AppResult<Arc<dyn Storage>> {
    Ok(Arc::new(S3Storage::new(config).await?))
}
