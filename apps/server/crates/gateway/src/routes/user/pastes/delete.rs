use actix_web::{delete, web, HttpResponse};
use iono_core::{web::ApiResult, AppError};

use crate::{auth::AuthedUser, state::AppState};

#[utoipa::path(
    delete,
    path = "/user/pastes/{id}",
    security(("bearer_auth" = [])),
    params(("id" = String, Path, description = "paste id")),
    responses((status = 204, description = "paste deleted"), (status = 404, description = "no such paste"))
)]
#[delete("/pastes/{id}")]
pub async fn delete_paste(
    state: web::Data<AppState>,
    user: AuthedUser,
    path: web::Path<String>,
) -> ApiResult<HttpResponse> {
    let deleted = sqlx::query_scalar::<_, String>(
        "DELETE FROM pastes WHERE id = $1 AND user_id = $2 RETURNING id",
    )
    .bind(path.into_inner())
    .bind(&user.0.id)
    .fetch_optional(&state.db)
    .await
    .map_err(AppError::from)?;

    if deleted.is_none() {
        return Err(AppError::NotFound.into());
    }

    Ok(HttpResponse::NoContent().finish())
}
