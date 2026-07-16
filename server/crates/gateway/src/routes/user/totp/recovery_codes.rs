use actix_web::{post, web, HttpResponse};
use iono_core::{auth::jwt, web::ApiResult, AppError};
use secrecy::ExposeSecret;

use crate::{auth::JwtUser, state::AppState};

use super::{replace_recovery_codes, require_reauth, ReauthRequest};

#[utoipa::path(
    post,
    path = "/user/totp/recovery-codes/regenerate",
    request_body = ReauthRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "returns new recovery codes and a new access token"),
        (status = 400, description = "validation failed"),
        (status = 401, description = "missing/invalid token or failed authentication")
    )
)]
#[post("/totp/recovery-codes/regenerate")]
pub async fn regenerate_recovery_codes(
    state: web::Data<AppState>,
    user: JwtUser,
    body: web::Json<ReauthRequest>,
) -> ApiResult<HttpResponse> {
    require_reauth(&user.0, &body).await?;

    let new_token_version = user.0.token_version + 1;

    let mut tx = state.db.begin().await.map_err(AppError::from)?;

    let recovery_codes = replace_recovery_codes(&mut tx, &user.0.id).await?;

    sqlx::query("UPDATE users SET token_version = $1 WHERE id = $2")
        .bind(new_token_version)
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
        "recovery_codes": recovery_codes,
        "access_token": access_token,
    })))
}
