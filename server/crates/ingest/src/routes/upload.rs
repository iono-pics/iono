use actix_multipart::Multipart;
use actix_web::{post, web, HttpResponse};
use futures_util::TryStreamExt;
use iono_core::{content_type, AppError};
use uuid::Uuid;

use crate::{error::ApiResult, state::AppState};

#[post("/upload")]
pub async fn upload_file(
    state: web::Data<AppState>,
    mut payload: Multipart,
) -> ApiResult<HttpResponse> {
    let mut field = payload
        .try_next()
        .await
        .map_err(|e| AppError::BadRequest(e.to_string()))?
        .ok_or_else(|| AppError::BadRequest("missing file field".into()))?;

    let max_size = state.config.max_upload_size_bytes;
    let mut data = Vec::new();
    while let Some(chunk) = field
        .try_next()
        .await
        .map_err(|e| AppError::BadRequest(e.to_string()))?
    {
        if data.len() + chunk.len() > max_size {
            return Err(AppError::BadRequest(format!(
                "file exceeds the {} MB limit",
                max_size / 1024 / 1024
            ))
            .into());
        }
        data.extend_from_slice(&chunk);
    }

    if data.is_empty() {
        return Err(AppError::BadRequest("uploaded file is empty".into()).into());
    }

    let (mime_type, data) = tokio::task::spawn_blocking(move || {
        let mime_type = content_type::detect(&data);
        (mime_type, data)
    })
    .await
    .map_err(|e| AppError::internal_from("content-type detection task panicked", e))?;

    let key = format!(
        "{}.{}",
        Uuid::new_v4(),
        content_type::extension_for(&mime_type)
    );

    state.storage.save(&key, &data, &mime_type).await?;
    let url = state.storage.public_url(&key, &mime_type).await?;

    Ok(HttpResponse::Created().json(serde_json::json!({ "url": url })))
}
