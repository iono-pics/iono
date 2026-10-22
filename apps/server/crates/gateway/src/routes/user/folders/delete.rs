use actix_web::{delete, web, HttpResponse};
use iono_core::{
    deletion::{self, Pending},
    web::{ApiResult, OptionExt},
    AppError,
};
use serde::Deserialize;

use crate::{auth::AuthedUser, state::AppState};

#[derive(Debug, Deserialize)]
pub struct DeleteFolderQuery {
    /// when true files in this folder are removed from storage and rows are dropped.
    /// defaults to false
    #[serde(default)]
    delete_files: bool,
}

#[utoipa::path(
    delete,
    path = "/user/folders/{id}",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "folder id"),
        ("delete_files" = Option<bool>, Query, description = "delete files in this subtree"),
    ),
    responses(
        (status = 204, description = "folder deleted"),
        (status = 401, description = "missing or invalid token"),
        (status = 404, description = "no such folder"),
    )
)]
#[delete("/folders/{id}")]
pub async fn delete_folder(
    state: web::Data<AppState>,
    user: AuthedUser,
    path: web::Path<String>,
    query: web::Query<DeleteFolderQuery>,
) -> ApiResult<HttpResponse> {
    let folder_id = path.into_inner();
    let user_id = &user.0.id;

    let mut tx = state.db.begin().await.map_err(AppError::from)?;

    let files: Vec<(String, String)> = if query.delete_files {
        sqlx::query_as::<_, (String, String)>(
            r#"
            WITH RECURSIVE folder_tree AS (
                SELECT id FROM folders WHERE id = $1 AND user_id = $2
                UNION ALL
                SELECT f.id FROM folders f
                INNER JOIN folder_tree ft ON f.parent_id = ft.id
                WHERE f.user_id = $2
            )
            DELETE FROM files
            WHERE user_id = $2
              AND folder_id IN (SELECT id FROM folder_tree)
            RETURNING id, original_name
            "#,
        )
        .bind(&folder_id)
        .bind(user_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(AppError::from)?
    } else {
        Vec::new()
    };

    let deleted = sqlx::query_scalar::<_, String>(
        "DELETE FROM folders WHERE id = $1 AND user_id = $2 RETURNING id",
    )
    .bind(&folder_id)
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::from)?;

    deleted.ok_or_not_found()?;

    let pending: Vec<Pending> = files
        .iter()
        .map(|(id, s3_key)| Pending::file(id, s3_key.clone()))
        .collect();
    let queued = deletion::enqueue(&mut *tx, &pending).await?;

    tx.commit().await.map_err(AppError::from)?;
    state.process_deletions(queued);

    Ok(HttpResponse::NoContent().finish())
}
