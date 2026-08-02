use actix_web::{post, web, HttpResponse};
use iono_core::{entities::Folder, web::ApiResult, AppError};
use serde::Deserialize;
use utoipa::ToSchema;
use uuid::Uuid;
use validator::{Validate, ValidationError};

use crate::{auth::AuthedUser, routes::user::folders::FolderSummary, state::AppState};

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct CreateFolderRequest {
    #[validate(
        length(min = 1, max = 64, message = "must be 1-64 characters"),
        custom(function = "validate_folder_name")
    )]
    name: String,
    parent_id: Option<String>,
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
    post,
    path = "/user/folders",
    request_body = CreateFolderRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 201, description = "folder created", body = FolderSummary),
        (status = 400, description = "validation failed"),
        (status = 401, description = "missing or invalid token"),
        (status = 404, description = "parent folder not found"),
        (status = 409, description = "a folder with that name already exists in this parent"),
    )
)]
#[post("/folders")]
pub async fn create_folder(
    state: web::Data<AppState>,
    user: AuthedUser,
    body: web::Json<CreateFolderRequest>,
) -> ApiResult<HttpResponse> {
    body.validate()
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    let body = body.into_inner();
    let id = Uuid::new_v4().to_string();

    let folder = sqlx::query_as::<_, Folder>(
        r#"
        INSERT INTO folders (id, user_id, parent_id, name)
        VALUES ($1, $2, $3, $4)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(&user.0.id)
    .bind(&body.parent_id)
    .bind(&body.name)
    .fetch_one(&state.db)
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

    Ok(HttpResponse::Created().json(FolderSummary::from(folder)))
}
