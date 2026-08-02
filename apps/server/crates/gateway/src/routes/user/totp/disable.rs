use actix_web::{post, web, HttpResponse};
use iono_core::{auth::jwt, web::ApiResult, AppError};
use secrecy::ExposeSecret;

use crate::{auth::JwtUser, state::AppState};

use super::{require_reauth, ReauthRequest};

#[utoipa::path(
    post,
    path = "/user/totp/disable",
    request_body = ReauthRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "totp disabled and returns a fresh access token"),
        (status = 400, description = "validation failed"),
        (status = 401, description = "missing/invalid token or failed authentication")
    )
)]
#[post("/totp/disable")]
pub async fn disable_totp(
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

    tx.commit().await.map_err(AppError::from)?;

    let access_token = jwt::issue_access_token(
        &user.0.id,
        new_token_version,
        state.config.jwt_secret.expose_secret(),
        state.config.jwt_access_ttl_minutes,
    )?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "access_token": access_token,
    })))
}
