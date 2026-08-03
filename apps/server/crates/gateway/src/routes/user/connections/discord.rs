use actix_web::{delete, post, web, HttpResponse};
use iono_core::{web::ApiResult, AppError};
use serde_json::json;

use crate::{
    auth::JwtUser,
    routes::auth::discord::{map_oauth_error, require_configured, store_flow_state},
    state::AppState,
};

#[utoipa::path(
    post,
    path = "/user/connections/discord/link",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "returns { url } to navigate the user to for authorization"),
        (status = 401, description = "missing or invalid token"),
    )
)]
#[post("/connections/discord/link")]
pub async fn start_link_discord(
    state: web::Data<AppState>,
    user: JwtUser,
) -> ApiResult<HttpResponse> {
    require_configured(&state.discord)?;

    let flow = state.discord.start_flow().map_err(map_oauth_error)?;
    store_flow_state(
        &state.db,
        &flow.csrf_token,
        &flow.pkce_verifier,
        Some(&user.0.id),
    )
    .await?;

    Ok(HttpResponse::Ok().json(json!({ "url": flow.authorize_url })))
}

#[utoipa::path(
    delete,
    path = "/user/connections/discord",
    security(("bearer_auth" = [])),
    responses(
        (status = 204, description = "discord unlinked"),
        (status = 401, description = "missing or invalid token"),
        (status = 404, description = "no linked discord account"),
    )
)]
#[delete("/connections/discord")]
pub async fn unlink_discord(state: web::Data<AppState>, user: JwtUser) -> ApiResult<HttpResponse> {
    let result =
        sqlx::query("DELETE FROM oauth_accounts WHERE user_id = $1 AND provider = 'discord'")
            .bind(&user.0.id)
            .execute(&state.db)
            .await
            .map_err(AppError::from)?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound.into());
    }

    Ok(HttpResponse::NoContent().finish())
}
