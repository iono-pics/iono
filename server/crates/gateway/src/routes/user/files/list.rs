use actix_web::{get, web, HttpResponse};
use chrono::{DateTime, Utc};
use iono_core::{entities::File, web::ApiResult, AppError};
use serde::{Deserialize, Serialize};
use sqlx::QueryBuilder;
use utoipa::ToSchema;
use validator::Validate;

use crate::{auth::AuthedUser, state::AppState};

const DEFAULT_LIMIT: i64 = 50;
const MAX_LIMIT: i64 = 200;

#[derive(Debug, Serialize, ToSchema)]
pub struct FileSummary {
    id: String,
    display_name: String,
    content_type: String,
    size_bytes: i64,
    folder_id: Option<String>,
    is_favourite: bool,
    password_protected: bool,
    expires_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

impl From<File> for FileSummary {
    fn from(file: File) -> Self {
        Self {
            id: file.id,
            display_name: file.display_name,
            content_type: file.content_type,
            size_bytes: file.size_bytes,
            folder_id: file.folder_id,
            is_favourite: file.is_favourite,
            password_protected: file.password_hash.is_some(),
            expires_at: file.expires_at,
            created_at: file.created_at,
        }
    }
}

#[derive(Debug, Deserialize, Validate)]
pub struct ListFilesQuery {
    folder_id: Option<String>,
    #[serde(default)]
    favourites_only: bool,
    #[validate(range(min = 1, max = 200, message = "must be between 1 and 200"))]
    limit: Option<i64>,
    #[validate(range(min = 0, message = "must be non-negative"))]
    offset: Option<i64>,
}

#[utoipa::path(
    get,
    path = "/user/files",
    security(("bearer_auth" = [])),
    params(
        ("folder_id" = Option<String>, Query, description = "filter to a specific folder id, or \"root\" for files with no folder"),
        ("favourites_only" = Option<bool>, Query, description = "only return files marked as favourites"),
        ("limit" = Option<i64>, Query, description = "page size, 1-200 (default 50)"),
        ("offset" = Option<i64>, Query, description = "offset for pagination, default 0"),
    ),
    responses(
        (status = 200, description = "the caller's files", body = [FileSummary]),
        (status = 400, description = "invalid query parameters"),
        (status = 401, description = "missing or invalid token"),
    )
)]
#[get("/files")]
pub async fn list_files(
    state: web::Data<AppState>,
    user: AuthedUser,
    query: web::Query<ListFilesQuery>,
) -> ApiResult<HttpResponse> {
    query
        .validate()
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    let query = query.into_inner();
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let offset = query.offset.unwrap_or(0);

    let mut sql: QueryBuilder<sqlx::Postgres> =
        QueryBuilder::new("SELECT * FROM files WHERE user_id = ");
    sql.push_bind(&user.0.id);
    sql.push(" AND (expires_at IS NULL OR expires_at > now())");

    if query.favourites_only {
        sql.push(" AND is_favourite");
    }

    match query.folder_id.as_deref() {
        Some("root") => {
            sql.push(" AND folder_id IS NULL");
        }
        Some(id) => {
            sql.push(" AND folder_id = ").push_bind(id.to_owned());
        }
        None => {}
    }

    sql.push(" ORDER BY created_at DESC LIMIT ")
        .push_bind(limit)
        .push(" OFFSET ")
        .push_bind(offset);

    let files = sql
        .build_query_as::<File>()
        .fetch_all(&state.db)
        .await
        .map_err(AppError::from)?;

    Ok(HttpResponse::Ok().json(files.into_iter().map(FileSummary::from).collect::<Vec<_>>()))
}
