use actix_multipart::Multipart;
use actix_web::{post, web, HttpResponse};
use futures_util::TryStreamExt;
use iono_core::AppError;
use uuid::Uuid;

use crate::{error::ApiResult, state::AppState};

// TODO: dont trust client for anything
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

    let content_type = field
        .content_type()
        .map(|m| m.to_string())
        .unwrap_or_else(|| "application/octet-stream".to_string());

    let extension = field
        .content_disposition()
        .and_then(|cd| cd.get_filename())
        .and_then(|name| name.rsplit_once('.'))
        .map(|(_, ext)| ext.to_string());

    let mut data = Vec::new();
    while let Some(chunk) = field
        .try_next()
        .await
        .map_err(|e| AppError::BadRequest(e.to_string()))?
    {
        data.extend_from_slice(&chunk);
    }

    let key = match extension {
        Some(ext) => format!("{}.{ext}", Uuid::new_v4()),
        None => Uuid::new_v4().to_string(),
    };

    state.storage.save(&key, &data, &content_type).await?;
    let url = state.storage.public_url(&key, &content_type).await?;

    Ok(HttpResponse::Created().json(serde_json::json!({ "url": url })))
}
