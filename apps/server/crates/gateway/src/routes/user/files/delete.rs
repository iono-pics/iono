use actix_web::{delete, web, HttpResponse};
use iono_core::{
    web::{ApiResult, OptionExt},
    AppError,
};

use crate::{auth::AuthedUser, state::AppState};

#[utoipa::path(
    delete,
    path = "/user/files/{id}",
    security(("bearer_auth" = [])),
    params(("id" = String, Path, description = "file id")),
    responses(
        (status = 204, description = "file deleted"),
        (status = 404, description = "no such file"),
    )
)]
#[delete("/files/{id}")]
pub async fn delete_file(
    state: web::Data<AppState>,
    user: AuthedUser,
    path: web::Path<String>,
) -> ApiResult<HttpResponse> {
    let file_id = path.into_inner();

    let s3_key = sqlx::query_scalar::<_, String>(
        "DELETE FROM files WHERE id = $1 AND user_id = $2 RETURNING original_name",
    )
    .bind(&file_id)
    .bind(&user.0.id)
    .fetch_optional(&state.db)
    .await
    .map_err(AppError::from)?
    .ok_or_not_found()?;

    if let Err(e) = state.storage.delete(&s3_key).await {
        tracing::warn!(
            file_id = %file_id,
            s3_key = %s3_key,
            error = %e,
            "failed to delete file object from storage, row already removed",
        );
    }

    Ok(HttpResponse::NoContent().finish())
}
