use actix_multipart::Multipart;
use actix_web::{post, web, HttpResponse};
use futures_util::TryStreamExt;
use iono_core::{content_type, entities::File, AppError};
use uuid::Uuid;

use crate::{auth::ApiKeyUser, error::ApiResult, state::AppState};

#[post("/upload")]
pub async fn upload_file(
    state: web::Data<AppState>,
    user: ApiKeyUser,
    mut payload: Multipart,
) -> ApiResult<HttpResponse> {
    let mut field = payload
        .try_next()
        .await
        .map_err(|e| AppError::BadRequest(e.to_string()))?
        .ok_or_else(|| AppError::BadRequest("missing file".into()))?;

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
        return Err(AppError::BadRequest("missing file".into()).into());
    }

    let (mime_type, data) = tokio::task::spawn_blocking(move || {
        let mime_type = content_type::detect(&data);
        (mime_type, data)
    })
    .await
    .map_err(|e| AppError::internal_from("content-type detection task panicked", e))?;

    let id = Uuid::new_v4().to_string();
    let key = format!(
        "{}.{}",
        Uuid::new_v4(),
        content_type::extension_for(&mime_type)
    );
    let size_bytes = data.len() as i64;

    let db = state.db.clone();
    let storage = state.storage.clone();
    let user_id = user.0.id.clone();
    let key_finalize = key.clone();
    let mime_type_finalize = mime_type.clone();

    let finalize = tokio::spawn(async move {
        storage
            .save(&key_finalize, &data, &mime_type_finalize)
            .await?;

        sqlx::query_as::<_, File>(
            r#"
            INSERT INTO files (id, user_id, key, content_type, size_bytes)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
            "#,
        )
        .bind(&id)
        .bind(&user_id)
        .bind(&key_finalize)
        .bind(&mime_type_finalize)
        .bind(size_bytes)
        .fetch_one(&db)
        .await
        .map_err(AppError::from)
    });

    let file = finalize
        .await
        .map_err(|e| AppError::internal_from("upload finalize panicked", e))??;

    let files_domain = sqlx::query_scalar::<_, String>(
        r#"
        SELECT d.name FROM domain_settings ds
        INNER JOIN domains d ON d.id = ds.files_domain_id
        WHERE ds.user_id = $1
        "#,
    )
    .bind(&user.0.id)
    .fetch_optional(&state.db)
    .await
    .map_err(AppError::from)?
    .ok_or_else(|| AppError::internal("user has no files domain configured"))?;

    Ok(HttpResponse::Created()
        .json(serde_json::json!({ "url": format!("https://{files_domain}/{}", file.key) })))
}
