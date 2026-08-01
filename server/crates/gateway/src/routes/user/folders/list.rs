use actix_web::{get, web, HttpResponse};
use iono_core::{entities::Folder, web::ApiResult, AppError};
use serde::Deserialize;
use sqlx::QueryBuilder;

use crate::{auth::AuthedUser, routes::user::folders::FolderSummary, state::AppState};

#[derive(Debug, Deserialize)]
pub struct ListFoldersQuery {
    /// filter folders under a specific parent or "root" for top level folders
    /// omit for entire tree
    parent_id: Option<String>,
}

#[utoipa::path(
    get,
    path = "/user/folders",
    security(("bearer_auth" = [])),
    params(
        ("parent_id" = Option<String>, Query, description = "filter to a parent folder id, or \"root\" for top level folders"),
    ),
    responses(
        (status = 200, description = "the caller's folders", body = [FolderSummary]),
        (status = 401, description = "missing or invalid token"),
    )
)]
#[get("/folders")]
pub async fn list_folders(
    state: web::Data<AppState>,
    user: AuthedUser,
    query: web::Query<ListFoldersQuery>,
) -> ApiResult<HttpResponse> {
    let query = query.into_inner();

    let mut sql: QueryBuilder<sqlx::Postgres> =
        QueryBuilder::new("SELECT * FROM folders WHERE user_id = ");
    sql.push_bind(&user.0.id);

    match query.parent_id.as_deref() {
        Some("root") => {
            sql.push(" AND parent_id IS NULL");
        }
        Some(id) => {
            sql.push(" AND parent_id = ").push_bind(id.to_owned());
        }
        None => {}
    }

    sql.push(" ORDER BY name ASC");

    let folders = sql
        .build_query_as::<Folder>()
        .fetch_all(&state.db)
        .await
        .map_err(AppError::from)?;

    Ok(HttpResponse::Ok().json(
        folders
            .into_iter()
            .map(FolderSummary::from)
            .collect::<Vec<_>>(),
    ))
}
