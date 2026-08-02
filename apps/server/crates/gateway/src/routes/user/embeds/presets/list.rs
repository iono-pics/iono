use actix_web::{get, web, HttpResponse};
use iono_core::{entities::EmbedPreset, web::ApiResult, AppError};

use crate::{
    auth::AuthedUser, routes::user::embeds::presets::EmbedPresetResponse, state::AppState,
};

#[utoipa::path(
    get,
    path = "/user/embeds/presets",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "the caller's embed presets", body = [EmbedPresetResponse]),
        (status = 401, description = "missing or invalid token"),
    )
)]
#[get("/embeds/presets")]
pub async fn list_embed_presets(
    state: web::Data<AppState>,
    user: AuthedUser,
) -> ApiResult<HttpResponse> {
    let presets = sqlx::query_as::<_, EmbedPreset>(
        "SELECT * FROM embed_presets WHERE user_id = $1 ORDER BY name ASC",
    )
    .bind(&user.0.id)
    .fetch_all(&state.db)
    .await
    .map_err(AppError::from)?;

    Ok(HttpResponse::Ok().json(
        presets
            .into_iter()
            .map(EmbedPresetResponse::from)
            .collect::<Vec<_>>(),
    ))
}
