use actix_web::{post, web, HttpResponse};
use iono_core::web::ApiResult;
use serde::Deserialize;
use utoipa::ToSchema;

use crate::state::AppState;

#[derive(Debug, Deserialize, ToSchema)]
pub struct LogoutRequest {
    refresh_token: String,
}

#[utoipa::path(
    post,
    path = "/auth/logout",
    request_body = LogoutRequest,
    responses((status = 204, description = "session ended, if the token matched one"))
)]
#[post("/logout")]
pub async fn logout(
    state: web::Data<AppState>,
    body: web::Json<LogoutRequest>,
) -> ApiResult<HttpResponse> {
    iono_core::auth::refresh::revoke(&state.db, &body.refresh_token).await?;

    Ok(HttpResponse::NoContent().finish())
}
