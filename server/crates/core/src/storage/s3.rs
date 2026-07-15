use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_sdk_s3::config::{Credentials, Region};
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{Delete, ObjectIdentifier};
use aws_sdk_s3::Client;
use secrecy::ExposeSecret;
use std::collections::HashSet;

use crate::config::Config;
use crate::error::{AppError, AppResult};
use crate::storage::{Storage, StoredObject};

#[derive(Clone)]
pub struct S3Storage {
    client: Client,
    bucket: String,
}

impl S3Storage {
    pub async fn new(config: &Config) -> AppResult<Self> {
        let mut loader = aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new(config.s3_region.clone()))
            .credentials_provider(Credentials::new(
                config.s3_access_key_id.clone(),
                config.s3_secret_access_key.expose_secret().to_string(),
                None,
                None,
                "iono-static",
            ));
        if let Some(endpoint) = &config.s3_endpoint {
            loader = loader.endpoint_url(endpoint.clone());
        }
        let shared_config = loader.load().await;

        let s3_config = aws_sdk_s3::config::Builder::from(&shared_config)
            .force_path_style(true)
            .build();

        Ok(Self {
            client: Client::from_conf(s3_config),
            bucket: config.s3_bucket.clone(),
        })
    }
}

#[async_trait]
impl Storage for S3Storage {
    async fn save(&self, key: &str, data: &[u8], content_type: &str) -> AppResult<()> {
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .content_type(content_type)
            .body(ByteStream::from(data.to_vec()))
            .send()
            .await
            .map_err(|e| AppError::internal_from("s3 put_object failed", e))?;
        Ok(())
    }

    async fn get(&self, key: &str, range: Option<&str>) -> AppResult<StoredObject> {
        let object = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .set_range(range.map(str::to_owned))
            .send()
            .await
            .map_err(|e| {
                if e.raw_response().map(|r| r.status().as_u16()) == Some(416) {
                    AppError::RangeNotSatisfiable
                } else {
                    AppError::internal_from("s3 get_object failed", e)
                }
            })?;

        let content_length = object
            .content_length()
            .and_then(|len| u64::try_from(len).ok());
        let content_range = object.content_range().map(str::to_owned);

        let stream = futures_util::stream::unfold(object.body, |mut body| async move {
            body.next()
                .await
                .map(|chunk| (chunk.map_err(std::io::Error::other), body))
        });

        Ok(StoredObject {
            stream: Box::pin(stream),
            content_length,
            content_range,
        })
    }

    async fn delete(&self, key: &str) -> AppResult<()> {
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| AppError::internal_from("s3 delete_object failed", e))?;
        Ok(())
    }

    async fn delete_many(&self, keys: &[String]) -> AppResult<Vec<String>> {
        let mut failed: HashSet<String> = HashSet::new();

        for chunk in keys.chunks(1000) {
            let objects = chunk
                .iter()
                .map(|key| ObjectIdentifier::builder().key(key).build())
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| AppError::internal_from("building delete identifiers failed", e))?;

            let delete = Delete::builder()
                .set_objects(Some(objects))
                .quiet(true)
                .build()
                .map_err(|e| AppError::internal_from("building delete request failed", e))?;

            let out = self
                .client
                .delete_objects()
                .bucket(&self.bucket)
                .delete(delete)
                .send()
                .await
                .map_err(|e| AppError::internal_from("s3 delete_objects failed", e))?;

            for err in out.errors() {
                if let Some(key) = err.key() {
                    tracing::warn!(key = %key, code = ?err.code(), "object delete failed");
                    failed.insert(key.to_owned());
                }
            }
        }

        Ok(keys
            .iter()
            .filter(|key| !failed.contains(*key))
            .cloned()
            .collect())
    }
}
