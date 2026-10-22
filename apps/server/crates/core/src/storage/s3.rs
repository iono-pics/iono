use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_sdk_s3::config::{Credentials, Region};
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{CompletedMultipartUpload, CompletedPart, Delete, ObjectIdentifier};
use aws_sdk_s3::Client;
use bytes::Bytes;
use futures_util::stream::BoxStream;
use futures_util::StreamExt;
use secrecy::ExposeSecret;
use std::collections::HashSet;

use crate::config::Config;
use crate::error::{AppError, AppResult};
use crate::storage::{Storage, StoredObject};

const PART_SIZE: usize = 8 * 1024 * 1024;

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

    async fn write_parts(
        &self,
        key: &str,
        content_type: &str,
        mut stream: BoxStream<'static, AppResult<Bytes>>,
        upload_id: &mut Option<String>,
    ) -> AppResult<()> {
        let mut buf: Vec<u8> = Vec::with_capacity(PART_SIZE);
        let mut parts: Vec<(i32, String)> = Vec::new();

        while let Some(chunk) = stream.next().await {
            buf.extend_from_slice(&chunk?);
            if buf.len() < PART_SIZE {
                continue;
            }

            let id = match upload_id {
                Some(id) => id.clone(),
                None => {
                    let id = self.begin_multipart(key, content_type).await?;
                    *upload_id = Some(id.clone());
                    id
                }
            };

            let body = std::mem::replace(&mut buf, Vec::with_capacity(PART_SIZE));
            let number = parts.len() as i32 + 1;
            let etag = self.put_part(key, &id, number, body).await?;
            parts.push((number, etag));
        }

        let Some(id) = upload_id.clone() else {
            return self.save(key, &buf, content_type).await;
        };

        if !buf.is_empty() {
            let number = parts.len() as i32 + 1;
            let etag = self.put_part(key, &id, number, buf).await?;
            parts.push((number, etag));
        }

        self.complete_multipart(key, &id, parts).await
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

    async fn save_stream(
        &self,
        key: &str,
        content_type: &str,
        stream: BoxStream<'static, AppResult<Bytes>>,
    ) -> AppResult<()> {
        let mut upload_id = None;
        let result = self
            .write_parts(key, content_type, stream, &mut upload_id)
            .await;

        if let (Err(_), Some(id)) = (&result, &upload_id) {
            if let Err(e) = self.abort_multipart(key, id).await {
                tracing::warn!(key = %key, error = %e, "could not abort multipart upload");
            }
        }

        result
    }

    async fn begin_multipart(&self, key: &str, content_type: &str) -> AppResult<String> {
        self.client
            .create_multipart_upload()
            .bucket(&self.bucket)
            .key(key)
            .content_type(content_type)
            .send()
            .await
            .map_err(|e| AppError::internal_from("s3 create_multipart_upload failed", e))?
            .upload_id()
            .map(str::to_owned)
            .ok_or_else(|| AppError::internal("s3 create_multipart_upload returned no upload id"))
    }

    async fn put_part(
        &self,
        key: &str,
        upload_id: &str,
        part_number: i32,
        body: Vec<u8>,
    ) -> AppResult<String> {
        let out = self
            .client
            .upload_part()
            .bucket(&self.bucket)
            .key(key)
            .upload_id(upload_id)
            .part_number(part_number)
            .body(ByteStream::from(body))
            .send()
            .await
            .map_err(|e| AppError::internal_from("s3 upload_part failed", e))?;

        out.e_tag()
            .map(str::to_owned)
            .ok_or_else(|| AppError::internal("s3 upload_part returned no etag"))
    }

    async fn complete_multipart(
        &self,
        key: &str,
        upload_id: &str,
        parts: Vec<(i32, String)>,
    ) -> AppResult<()> {
        let parts = parts
            .into_iter()
            .map(|(number, etag)| {
                CompletedPart::builder()
                    .part_number(number)
                    .e_tag(etag)
                    .build()
            })
            .collect();

        self.client
            .complete_multipart_upload()
            .bucket(&self.bucket)
            .key(key)
            .upload_id(upload_id)
            .multipart_upload(
                CompletedMultipartUpload::builder()
                    .set_parts(Some(parts))
                    .build(),
            )
            .send()
            .await
            .map_err(|e| AppError::internal_from("s3 complete_multipart_upload failed", e))?;

        Ok(())
    }

    async fn abort_multipart(&self, key: &str, upload_id: &str) -> AppResult<()> {
        self.client
            .abort_multipart_upload()
            .bucket(&self.bucket)
            .key(key)
            .upload_id(upload_id)
            .send()
            .await
            .map_err(|e| AppError::internal_from("s3 abort_multipart_upload failed", e))?;
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
