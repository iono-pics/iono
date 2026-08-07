use actix_web::{post, web, HttpRequest, HttpResponse};
use iono_core::{
    auth::{jwt, refresh, refresh::SessionContext},
    entities::User,
    web::ApiResult,
    AppError,
};
use secrecy::ExposeSecret;
use serde::Deserialize;
use utoipa::ToSchema;

use crate::{routes::auth::signed_in_payload, state::AppState};

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
    req: HttpRequest,
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

    if user.is_permanently_deleted(state.config.recovery_window_days) {
        return Err(AppError::Gone(format!(
            "recovery window of {} days has expired",
            state.config.recovery_window_days
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

    refresh::revoke_all_for_user(&state.db, &user.id).await?;

    let payload = signed_in_payload(
        &state,
        &user.id,
        new_token_version,
        &SessionContext::from_request(&req),
    )
    .await?;

    Ok(HttpResponse::Ok().json(payload))
}
