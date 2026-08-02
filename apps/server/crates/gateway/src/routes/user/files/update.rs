use actix_web::{patch, web, HttpResponse};
use chrono::{DateTime, Utc};
use iono_core::{
    auth::password::hash_password_async,
    entities::File,
    validators,
    web::{ApiResult, MapDbError, OptionExt, Patch},
    AppError,
};
use serde::Deserialize;
use utoipa::ToSchema;
use validator::{Validate, ValidationError};

use crate::{auth::AuthedUser, routes::user::files::list::FileSummary, state::AppState};

#[derive(Debug, Default, Deserialize, Validate, ToSchema)]
#[serde(default)]
pub struct UpdateFileRequest {
    #[validate(
        length(min = 1, max = 128, message = "must be 1-128 characters"),
        custom(function = "validate_display_name")
    )]
    display_name: Option<String>,
    is_favourite: Option<bool>,
    #[schema(value_type = Option<String>)]
    folder_id: Patch<String>,
    #[schema(value_type = Option<DateTime<Utc>>)]
    expires_at: Patch<DateTime<Utc>>,
    #[schema(value_type = Option<String>)]
    password: Patch<String>,
}

fn validate_display_name(value: &str) -> Result<(), ValidationError> {
    if value
        .chars()
        .any(|c| matches!(c, '/' | '\\' | '?' | '#') || c.is_control())
    {
        return Err(ValidationError::new("display_name_chars")
            .with_message("must not contain '/', '\\\\', '?', '#' or control characters".into()));
    }
    Ok(())
}

#[utoipa::path(
    patch,
    path = "/user/files/{id}",
    request_body = UpdateFileRequest,
    security(("bearer_auth" = [])),
    params(("id" = String, Path, description = "file id")),
    responses(
        (status = 200, description = "file updated", body = FileSummary),
        (status = 400, description = "validation failed"),
        (status = 401, description = "missing or invalid token"),
        (status = 404, description = "no such file"),
        (status = 409, description = "that name is already in use"),
    )
)]
#[patch("/files/{id}")]
pub async fn update_file(
    state: web::Data<AppState>,
    user: AuthedUser,
    path: web::Path<String>,
    body: web::Json<UpdateFileRequest>,
) -> ApiResult<HttpResponse> {
    body.validate()
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    let body = body.into_inner();

    if body.display_name.is_none()
        && body.is_favourite.is_none()
        && !body.folder_id.is_provided()
        && !body.expires_at.is_provided()
        && !body.password.is_provided()
    {
        return Err(AppError::BadRequest("no fields to update".into()).into());
    }

    if let Some(at) = body.expires_at.as_set() {
        validators::future_datetime(*at)?;
    }

    if let Some(pw) = body.password.as_set() {
        validators::password(pw, 256)?;
    }

    let (folder_provided, folder_value) = body.folder_id.split();
    let (expires_provided, expires_value) = body.expires_at.split();
    let (password_provided, password_plain) = body.password.split();
    let password_hash: Option<String> = match password_plain {
        Some(pw) => Some(hash_password_async(pw).await?),
        None => None,
    };

    let file_id = path.into_inner();

    let old_display_name: Option<String> = if body.display_name.is_some() {
        sqlx::query_scalar("SELECT display_name FROM files WHERE id = $1 AND user_id = $2")
            .bind(&file_id)
            .bind(&user.0.id)
            .fetch_optional(&state.db)
            .await
            .map_err(AppError::from)?
    } else {
        None
    };

    let updated = sqlx::query_as::<_, File>(
        r#"
        UPDATE files SET
            display_name  = COALESCE($1, display_name),
            is_favourite  = COALESCE($2, is_favourite),
            folder_id     = CASE WHEN $3 THEN $4 ELSE folder_id END,
            expires_at    = CASE WHEN $5 THEN $6 ELSE expires_at END,
            password_hash = CASE WHEN $7 THEN $8 ELSE password_hash END
        WHERE id = $9 AND user_id = $10
        RETURNING *
        "#,
    )
    .bind(&body.display_name)
    .bind(body.is_favourite)
    .bind(folder_provided)
    .bind(&folder_value)
    .bind(expires_provided)
    .bind(expires_value)
    .bind(password_provided)
    .bind(&password_hash)
    .bind(&file_id)
    .bind(&user.0.id)
    .fetch_optional(&state.db)
    .await
    .map_err(
        MapDbError::new()
            .on_unique_conflict("that name is already in use")
            .on_foreign_key_not_found()
            .build(),
    )?;

    let file = updated.ok_or_not_found()?;

    let renamed_from = old_display_name.filter(|old| old != &file.display_name);
    if (password_provided || renamed_from.is_some()) && state.cloudflare.is_configured() {
        let mut display_names: Vec<&str> = vec![&file.display_name];
        if let Some(old) = renamed_from.as_deref() {
            display_names.push(old);
        }
        let urls = iono_core::urls::file_urls(&state.db, &user.0.id, &display_names).await?;
        if !urls.is_empty() {
            let cf = state.cloudflare.clone();
            let file_id = file.id.clone();
            tokio::spawn(async move {
                if let Err(e) = cf.purge_urls(urls).await {
                    tracing::warn!(file_id = %file_id, error = %e, "cloudflare purge failed");
                }
            });
        }
    }

    Ok(HttpResponse::Ok().json(FileSummary::from(file)))
}
