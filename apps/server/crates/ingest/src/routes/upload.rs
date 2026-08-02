use actix_multipart::form::{bytes::Bytes, text::Text, MultipartForm};
use actix_web::{post, web, HttpResponse};
use chrono::{Duration, Utc};
use iono_core::{
    auth::{password::hash_password_async, token},
    content_type,
    entities::{File, UserSettings},
    AppError,
};
use utoipa::ToSchema;
use uuid::Uuid;

use iono_core::web::{append_password_query, ApiResult};

use crate::{auth::ApiKeyUser, state::AppState};

#[derive(MultipartForm, ToSchema)]
pub struct UploadForm {
    #[schema(value_type = String, format = Binary)]
    file: Bytes,
    #[schema(value_type = Option<String>)]
    password: Option<Text<String>>,
}

#[utoipa::path(
    post,
    path = "/",
    request_body(content = UploadForm, content_type = "multipart/form-data"),
    security(("bearer_auth" = [])),
    responses(
        (status = 201, description = "file uploaded"),
        (status = 400, description = "missing or malformed file"),
        (status = 401, description = "missing or invalid api key"),
        (status = 402, description = "plan size or storage quota exceeded")
    )
)]
#[post("/")]
pub async fn upload_file(
    state: web::Data<AppState>,
    user: ApiKeyUser,
    MultipartForm(form): MultipartForm<UploadForm>,
) -> ApiResult<HttpResponse> {
    let data = form.file.data;

    if data.is_empty() {
        return Err(AppError::BadRequest("missing file".into()).into());
    }

    let plain_password = form
        .password
        .map(|t| t.into_inner())
        .filter(|p| !p.is_empty());
    let password_hash = match plain_password.clone() {
        Some(p) => Some(hash_password_async(p).await?),
        None => None,
    };

    iono_core::quota::check_before_upload(&state.db, &user.0.id, data.len() as i64).await?;

    let settings =
        sqlx::query_as::<_, UserSettings>("SELECT * FROM user_settings WHERE user_id = $1")
            .bind(&user.0.id)
            .fetch_optional(&state.db)
            .await
            .map_err(AppError::from)?
            .ok_or_else(|| AppError::internal("user has no settings configured"))?;

    let expires_at = settings
        .default_expires_in_seconds
        .map(|secs| Utc::now() + Duration::seconds(secs));

    let (mime_type, data) = tokio::task::spawn_blocking(move || {
        let mime_type = content_type::detect(&data);
        (mime_type, data)
    })
    .await
    .map_err(|e| AppError::internal_from("content-type detection task panicked", e))?;

    let id = Uuid::new_v4().to_string();
    let extension = content_type::extension_for(&mime_type);
    let s3_key = format!("{}.{extension}", Uuid::new_v4());
    let display_name_stem = token::generate_display_name(
        settings.display_name_length as usize,
        &settings.display_name_style,
    );
    let display_name = if settings.display_name_include_extension {
        format!("{display_name_stem}.{extension}")
    } else {
        display_name_stem
    };
    let size_bytes = data.len() as i64;

    let db = state.db.clone();
    let storage = state.storage.clone();
    let user_id = user.0.id.clone();
    let s3_key_finalize = s3_key.clone();
    let display_name_finalize = display_name.clone();
    let mime_type_finalize = mime_type.clone();

    // detached so a client disconnecting cant cancel between the S3 write and db insert
    let finalize = tokio::spawn(async move {
        storage
            .save(&s3_key_finalize, &data, &mime_type_finalize)
            .await?;

        sqlx::query_as::<_, File>(
            r#"
            INSERT INTO files (id, user_id, display_name, original_name, content_type, size_bytes, password_hash, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING *
            "#,
        )
        .bind(&id)
        .bind(&user_id)
        .bind(&display_name_finalize)
        .bind(&s3_key_finalize)
        .bind(&mime_type_finalize)
        .bind(size_bytes)
        .bind(&password_hash)
        .bind(expires_at)
        .fetch_one(&db)
        .await
        .map_err(AppError::from)
    });

    let file = finalize
        .await
        .map_err(|e| AppError::internal_from("upload finalize panicked", e))??;

    let (files_domain, files_path_prefix) = sqlx::query_as::<_, (String, Option<String>)>(
        r#"
        SELECT d.name, ds.files_path_prefix
        FROM domain_settings ds
        INNER JOIN domains d ON d.id = ds.files_domain_id
        WHERE ds.user_id = $1
        "#,
    )
    .bind(&user.0.id)
    .fetch_optional(&state.db)
    .await
    .map_err(AppError::from)?
    .ok_or_else(|| AppError::internal("user has no files domain configured"))?;

    let prefix = files_path_prefix
        .map(|p| format!("{p}/"))
        .unwrap_or_default();

    let base_url = if settings.raw_links_only {
        format!("https://{files_domain}/{prefix}raw/{}", file.display_name)
    } else {
        format!("https://{files_domain}/{prefix}{}", file.display_name)
    };
    let url = append_password_query(&base_url, plain_password.as_deref());

    Ok(HttpResponse::Created().json(serde_json::json!({ "url": url })))
}
