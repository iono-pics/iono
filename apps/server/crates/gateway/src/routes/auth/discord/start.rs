use actix_web::{get, http::header, web, HttpResponse};
use iono_core::web::ApiResult;

use crate::{
    routes::auth::discord::{map_oauth_error, require_configured, store_flow_state},
    state::AppState,
};

#[utoipa::path(
    get,
    path = "/auth/discord",
    responses(
        (status = 302, description = "redirect to discord's authorize page"),
    )
)]
#[get("/discord")]
pub async fn discord_start(state: web::Data<AppState>) -> ApiResult<HttpResponse> {
    require_configured(&state.discord)?;

    let flow = state.discord.start_flow().map_err(map_oauth_error)?;
    store_flow_state(
        &state.db,
        &flow.csrf_token,
        &flow.pkce_verifier,
        None,
        state.config.oauth_flow_state_ttl_minutes,
    )
    .await?;

    Ok(HttpResponse::Found()
        .append_header((header::LOCATION, flow.authorize_url))
        .finish())
}
