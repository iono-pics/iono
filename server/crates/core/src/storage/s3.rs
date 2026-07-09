use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_sdk_s3::config::{Credentials, Region};
use aws_sdk_s3::presigning::PresigningConfig;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::Client;
use secrecy::ExposeSecret;
use std::time::Duration;

use crate::config::Config;
use crate::error::{AppError, AppResult};
use crate::storage::Storage;

#[derive(Clone)]
pub struct S3Storage {
    client: Client,
    bucket: String,
    public_url_base: Option<String>,
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
            public_url_base: config.s3_public_url_base.clone(),
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

    async fn public_url(&self, key: &str, content_type: &str) -> AppResult<String> {
        if let Some(base) = &self.public_url_base {
            return Ok(format!("{}/{key}", base.trim_end_matches('/')));
        }

        let presigned = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .response_content_type(content_type)
            .presigned(
                PresigningConfig::expires_in(Duration::from_secs(3600))
                    .map_err(|e| AppError::internal_from("presign config failed", e))?,
            )
            .await
            .map_err(|e| AppError::internal_from("s3 presign failed", e))?;

        Ok(presigned.uri().to_string())
    }
}
