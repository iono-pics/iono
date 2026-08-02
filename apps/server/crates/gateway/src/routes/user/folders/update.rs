use actix_web::{patch, web, HttpResponse};
use iono_core::{entities::Folder, web::ApiResult, AppError};
use serde::{Deserialize, Deserializer};
use utoipa::ToSchema;
use validator::{Validate, ValidationError};

use crate::{auth::AuthedUser, routes::user::folders::FolderSummary, state::AppState};

#[derive(Debug, Default, Deserialize, Validate, ToSchema)]
pub struct UpdateFolderRequest {
    #[validate(
        length(min = 1, max = 64, message = "must be 1-64 characters"),
        custom(function = "validate_folder_name")
    )]
    name: Option<String>,
    /// 'null' moves folder to root, a folder id puts it under that folder
    /// and omitting this field leaves the parent unchanged
    #[serde(default, deserialize_with = "deserialize_some")]
    parent_id: Option<Option<String>>,
}

fn deserialize_some<'de, T, D>(deserializer: D) -> Result<Option<T>, D::Error>
where
    T: Deserialize<'de>,
    D: Deserializer<'de>,
{
    T::deserialize(deserializer).map(Some)
}

fn validate_folder_name(value: &str) -> Result<(), ValidationError> {
    if value.trim() != value {
        return Err(ValidationError::new("folder_name_whitespace")
            .with_message("must not have leading or trailing whitespace".into()));
    }
    if value.chars().any(|c| c.is_control() || c == '/') {
        return Err(ValidationError::new("folder_name_chars")
            .with_message("must not contain '/' or control characters".into()));
    }
    Ok(())
}

#[utoipa::path(
    patch,
    path = "/user/folders/{id}",
    request_body = UpdateFolderRequest,
    security(("bearer_auth" = [])),
    params(("id" = String, Path, description = "folder id")),
    responses(
        (status = 200, description = "folder updated", body = FolderSummary),
        (status = 400, description = "validation failed"),
        (status = 401, description = "missing or invalid token"),
        (status = 404, description = "folder or new parent not found"),
        (status = 409, description = "folder name already used or move would create a cycle"),
    )
)]
#[patch("/folders/{id}")]
pub async fn update_folder(
    state: web::Data<AppState>,
    user: AuthedUser,
    path: web::Path<String>,
    body: web::Json<UpdateFolderRequest>,
) -> ApiResult<HttpResponse> {
    body.validate()
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    let body = body.into_inner();

    if body.name.is_none() && body.parent_id.is_none() {
        return Err(AppError::BadRequest("no fields to update".into()).into());
    }

    let folder_id = path.into_inner();
    let parent_provided = body.parent_id.is_some();
    let new_parent = body.parent_id.clone().flatten();

    if let Some(ref new_parent_id) = new_parent {
        if new_parent_id == &folder_id {
            return Err(AppError::Conflict("a folder cannot be its own parent".into()).into());
        }
        if would_create_cycle(&state, &user.0.id, &folder_id, new_parent_id).await? {
            return Err(AppError::Conflict("moving here would create a cycle".into()).into());
        }
    }

    let updated = sqlx::query_as::<_, Folder>(
        r#"
        UPDATE folders SET
            name      = COALESCE($1, name),
            parent_id = CASE WHEN $2 THEN $3 ELSE parent_id END
        WHERE id = $4 AND user_id = $5
        RETURNING *
        "#,
    )
    .bind(&body.name)
    .bind(parent_provided)
    .bind(&new_parent)
    .bind(&folder_id)
    .bind(&user.0.id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| match &e {
        sqlx::Error::Database(db_err)
            if db_err.kind() == sqlx::error::ErrorKind::UniqueViolation =>
        {
            AppError::Conflict("a folder with that name already exists in this parent".into())
        }
        sqlx::Error::Database(db_err)
            if db_err.kind() == sqlx::error::ErrorKind::ForeignKeyViolation =>
        {
            AppError::NotFound
        }
        _ => AppError::from(e),
    })?;

    let Some(folder) = updated else {
        return Err(AppError::NotFound.into());
    };

    Ok(HttpResponse::Ok().json(FolderSummary::from(folder)))
}

async fn would_create_cycle(
    state: &AppState,
    user_id: &str,
    folder_id: &str,
    new_parent_id: &str,
) -> Result<bool, AppError> {
    let found: Option<String> = sqlx::query_scalar(
        r#"
        WITH RECURSIVE ancestors AS (
            SELECT id, parent_id
            FROM folders
            WHERE id = $1 AND user_id = $2
            UNION ALL
            SELECT f.id, f.parent_id
            FROM folders f
            INNER JOIN ancestors a ON f.id = a.parent_id
            WHERE f.user_id = $2
        )
        SELECT id FROM ancestors WHERE id = $3 LIMIT 1
        "#,
    )
    .bind(new_parent_id)
    .bind(user_id)
    .bind(folder_id)
    .fetch_optional(&state.db)
    .await?;

    Ok(found.is_some())
}
