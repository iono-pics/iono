use actix_web::{post, web, HttpResponse};
use iono_core::{
    auth::jwt,
    entities::{User, RECOVERY_WINDOW_DAYS},
    web::ApiResult,
    AppError,
};
use secrecy::ExposeSecret;
use serde::Deserialize;
use serde_json::json;
use utoipa::ToSchema;

use crate::state::AppState;

#[derive(Debug, Deserialize, ToSchema)]
pub struct RestoreRequest {
    restore_token: String,
}

#[utoipa::path(
    post,
    path = "/auth/restore",
    request_body = RestoreRequest,
    responses(
        (status = 200, description = "account restored; returns an access token"),
        (status = 401, description = "invalid or expired restore token"),
        (status = 410, description = "recovery window has expired"),
    )
)]
#[post("/restore")]
pub async fn restore(
    state: web::Data<AppState>,
    body: web::Json<RestoreRequest>,
) -> ApiResult<HttpResponse> {
    let claims =
        jwt::verify_restore_token(&body.restore_token, state.config.jwt_secret.expose_secret())?;

    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
        .bind(&claims.sub)
        .fetch_optional(&state.db)
        .await
        .map_err(AppError::from)?
        .ok_or(AppError::Unauthorized)?;

    if user.deleted_at.is_none() {
        return Err(AppError::Unauthorized.into());
    }

    if user.is_permanently_deleted() {
        return Err(AppError::Gone(format!(
            "recovery window of {RECOVERY_WINDOW_DAYS} days has expired"
        ))
        .into());
    }

    let new_token_version: i32 = sqlx::query_scalar(
        r#"
        UPDATE users SET
            deleted_at    = NULL,
            token_version = token_version + 1
        WHERE id = $1
        RETURNING token_version
        "#,
    )
    .bind(&user.id)
    .fetch_one(&state.db)
    .await
    .map_err(AppError::from)?;

    let access_token = jwt::issue_access_token(
        &user.id,
        new_token_version,
        state.config.jwt_secret.expose_secret(),
        state.config.jwt_access_ttl_minutes,
    )?;

    Ok(HttpResponse::Ok().json(json!({ "access_token": access_token })))
}
