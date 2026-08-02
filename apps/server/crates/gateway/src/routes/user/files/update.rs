use actix_web::{patch, web, HttpResponse};
use chrono::{DateTime, Utc};
use iono_core::{auth::password::hash_password_async, entities::File, web::ApiResult, AppError};
use serde::{Deserialize, Deserializer};
use utoipa::ToSchema;
use validator::{Validate, ValidationError};

use crate::{auth::AuthedUser, routes::user::files::list::FileSummary, state::AppState};

const MAX_PASSWORD_LEN: usize = 256;

#[derive(Debug, Default, Deserialize, Validate, ToSchema)]
pub struct UpdateFileRequest {
    #[validate(
        length(min = 1, max = 128, message = "must be 1-128 characters"),
        custom(function = "validate_display_name")
    )]
    display_name: Option<String>,
    is_favourite: Option<bool>,
    #[serde(default, deserialize_with = "deserialize_some")]
    folder_id: Option<Option<String>>,
    #[serde(default, deserialize_with = "deserialize_some")]
    expires_at: Option<Option<DateTime<Utc>>>,
    #[serde(default, deserialize_with = "deserialize_some")]
    password: Option<Option<String>>,
}

fn deserialize_some<'de, T, D>(deserializer: D) -> Result<Option<T>, D::Error>
where
    T: Deserialize<'de>,
    D: Deserializer<'de>,
{
    T::deserialize(deserializer).map(Some)
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
        (status = 409, description = "display name already in use"),
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
        && body.folder_id.is_none()
        && body.expires_at.is_none()
        && body.password.is_none()
    {
        return Err(AppError::BadRequest("no fields to update".into()).into());
    }

    if let Some(Some(at)) = body.expires_at {
        if at <= Utc::now() {
            return Err(AppError::BadRequest("expires_at must be in the future".into()).into());
        }
    }

    if let Some(Some(pw)) = &body.password {
        if pw.is_empty() || pw.len() > MAX_PASSWORD_LEN {
            return Err(AppError::BadRequest(format!(
                "password must be 1-{MAX_PASSWORD_LEN} characters, or null to clear"
            ))
            .into());
        }
    }

    let expires_provided = body.expires_at.is_some();
    let expires_value = body.expires_at.flatten();

    let folder_provided = body.folder_id.is_some();
    let folder_value = body.folder_id.flatten();

    let password_provided = body.password.is_some();
    let password_hash: Option<String> = match body.password.flatten() {
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
    .map_err(|e| match &e {
        sqlx::Error::Database(db_err)
            if db_err.kind() == sqlx::error::ErrorKind::UniqueViolation =>
        {
            AppError::Conflict("display_name already in use".into())
        }
        sqlx::Error::Database(db_err)
            if db_err.kind() == sqlx::error::ErrorKind::ForeignKeyViolation =>
        {
            AppError::NotFound
        }
        _ => AppError::from(e),
    })?;

    let Some(file) = updated else {
        return Err(AppError::NotFound.into());
    };

    let renamed_from = old_display_name.filter(|old| old != &file.display_name);
    if password_provided || renamed_from.is_some() {
        let mut display_names = vec![file.display_name.clone()];
        if let Some(old) = renamed_from {
            display_names.push(old);
        }
        if let Some(urls) = file_urls(&state, &user.0.id, &display_names).await? {
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

async fn file_urls(
    state: &AppState,
    user_id: &str,
    display_names: &[String],
) -> Result<Option<Vec<String>>, AppError> {
    if !state.cloudflare.is_configured() || display_names.is_empty() {
        return Ok(None);
    }
    let domain: Option<(String, Option<String>)> = sqlx::query_as(
        r#"
        SELECT d.name, ds.files_path_prefix
        FROM domain_settings ds
        INNER JOIN domains d ON d.id = ds.files_domain_id
        WHERE ds.user_id = $1
        "#,
    )
    .bind(user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(AppError::from)?;

    let Some((host, prefix)) = domain else {
        return Ok(None);
    };
    let prefix = prefix.map(|p| format!("{p}/")).unwrap_or_default();

    let mut urls = Vec::with_capacity(display_names.len() * 2);
    for name in display_names {
        urls.push(format!("https://{host}/{prefix}{name}"));
        urls.push(format!("https://{host}/{prefix}raw/{name}"));
    }
    Ok(Some(urls))
}
