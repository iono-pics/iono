use actix_web::{post, web, HttpRequest, HttpResponse};
use iono_core::{
    auth::{refresh, refresh::SessionContext},
    web::ApiResult,
    AppError,
};

use crate::{auth::JwtUser, routes::auth::signed_in_payload, state::AppState};

use super::{require_reauth, ReauthRequest};

#[utoipa::path(
    post,
    path = "/user/totp/disable",
    request_body = ReauthRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "totp disabled, other sessions ended, returns a fresh token pair"),
        (status = 400, description = "validation failed"),
        (status = 401, description = "missing/invalid token or failed authentication")
    )
)]
#[post("/totp/disable")]
pub async fn disable_totp(
    req: HttpRequest,
    state: web::Data<AppState>,
    user: JwtUser,
    body: web::Json<ReauthRequest>,
) -> ApiResult<HttpResponse> {
    require_reauth(&user.0, &body).await?;

    let new_token_version = user.0.token_version + 1;

    let mut tx = state.db.begin().await.map_err(AppError::from)?;

    sqlx::query(
        "UPDATE users SET totp_enabled = false, totp_secret = NULL, token_version = $1 WHERE id = $2",
    )
    .bind(new_token_version)
    .bind(&user.0.id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::from)?;

    sqlx::query("DELETE FROM totp_recovery_codes WHERE user_id = $1")
        .bind(&user.0.id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::from)?;

    refresh::revoke_all_for_user(&mut *tx, &user.0.id).await?;

    tx.commit().await.map_err(AppError::from)?;

    let payload = signed_in_payload(
        &state,
        &user.0.id,
        new_token_version,
        &SessionContext::from_request(&req),
    )
    .await?;

    Ok(HttpResponse::Ok().json(payload))
}
