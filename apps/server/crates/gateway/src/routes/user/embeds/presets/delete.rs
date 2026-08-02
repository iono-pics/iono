use actix_web::{delete, web, HttpResponse};
use iono_core::{
    web::{ApiResult, MapDbError, OptionExt},
    AppError,
};

use crate::{auth::AuthedUser, state::AppState};

#[utoipa::path(
    delete,
    path = "/user/embeds/presets/{id}",
    security(("bearer_auth" = [])),
    params(("id" = String, Path, description = "preset id")),
    responses(
        (status = 204, description = "preset deleted"),
        (status = 401, description = "missing or invalid token"),
        (status = 404, description = "no such preset"),
        (status = 409, description = "preset is currently in use as the active preset"),
    )
)]
#[delete("/embeds/presets/{id}")]
pub async fn delete_embed_preset(
    state: web::Data<AppState>,
    user: AuthedUser,
    path: web::Path<String>,
) -> ApiResult<HttpResponse> {
    sqlx::query_scalar::<_, String>(
        "DELETE FROM embed_presets WHERE id = $1 AND user_id = $2 RETURNING id",
    )
    .bind(path.into_inner())
    .bind(&user.0.id)
    .fetch_optional(&state.db)
    .await
    .map_err(
        MapDbError::new()
            .on_foreign_key(AppError::Conflict(
                "cannot delete the currently active preset, switch or disable embeds first".into(),
            ))
            .build(),
    )?
    .ok_or_not_found()?;

    Ok(HttpResponse::NoContent().finish())
}
