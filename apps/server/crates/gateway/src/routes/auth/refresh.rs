use actix_web::{post, web, HttpRequest, HttpResponse};
use iono_core::{
    auth::{jwt, refresh::SessionContext},
    web::ApiResult,
};
use secrecy::ExposeSecret;
use serde::Deserialize;
use utoipa::ToSchema;

use crate::{routes::auth::access_token_payload, state::AppState};

#[derive(Debug, Deserialize, ToSchema)]
pub struct RefreshRequest {
    refresh_token: String,
}

#[utoipa::path(
    post,
    path = "/auth/refresh",
    request_body = RefreshRequest,
    responses(
        (status = 200, description = "returns a new access token and refresh token"),
        (status = 401, description = "unknown, expired, revoked, or used refresh token")
    )
)]
#[post("/refresh")]
pub async fn refresh(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<RefreshRequest>,
) -> ApiResult<HttpResponse> {
    let ctx = SessionContext::from_request(&req);

    let (user, refresh_token) = iono_core::auth::refresh::rotate(
        &state.db,
        &body.refresh_token,
        state.config.refresh_token_ttl_days,
        &ctx,
    )
    .await?;

    let access_token = jwt::issue_access_token(
        &user.id,
        user.token_version,
        state.config.jwt_secret.expose_secret(),
        state.config.jwt_access_ttl_minutes,
    )?;

    Ok(HttpResponse::Ok().json(access_token_payload(access_token, refresh_token, &state)))
}
