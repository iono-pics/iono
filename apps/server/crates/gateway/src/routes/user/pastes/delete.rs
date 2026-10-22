use actix_web::{delete, web, HttpResponse};
use iono_core::{
    deletion::{self, Pending},
    web::{ApiResult, OptionExt},
    AppError,
};

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
    let mut tx = state.db.begin().await.map_err(AppError::from)?;

    let paste_id = sqlx::query_scalar::<_, String>(
        "DELETE FROM pastes WHERE id = $1 AND user_id = $2 RETURNING id",
    )
    .bind(path.into_inner())
    .bind(&user.0.id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::from)?
    .ok_or_not_found()?;

    let queued =
        deletion::enqueue(&mut *tx, &[Pending::tag(deletion::paste_tag(&paste_id))]).await?;
    tx.commit().await.map_err(AppError::from)?;
    state.process_deletions(queued);

    Ok(HttpResponse::NoContent().finish())
}
