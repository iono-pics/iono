use actix_web::{patch, web, HttpResponse};
use iono_core::{auth::jwt, web::ApiResult, AppError};
use secrecy::ExposeSecret;
use serde::Deserialize;
use utoipa::ToSchema;

use crate::{
    auth::JwtUser,
    routes::user::totp::{require_reauth, ReauthRequest},
    state::AppState,
};

#[derive(Debug, Deserialize, ToSchema)]
pub struct RequirePasskeyRequest {
    required: bool,
    #[serde(flatten)]
    reauth: ReauthRequest,
}

#[utoipa::path(
    patch,
    path = "/user/passkeys/require",
    request_body = RequirePasskeyRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "passkey requirement updated and returns a new access token"),
        (status = 400, description = "validation failed, or enabling requires at least one registered passkey"),
        (status = 401, description = "missing/invalid token or failed authentication")
    )
)]
#[patch("/passkeys/require")]
pub async fn require_passkey(
    state: web::Data<AppState>,
    user: JwtUser,
    body: web::Json<RequirePasskeyRequest>,
) -> ApiResult<HttpResponse> {
    require_reauth(&user.0, &body.reauth).await?;

    if body.required {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM passkeys WHERE user_id = $1")
            .bind(&user.0.id)
            .fetch_one(&state.db)
            .await
            .map_err(AppError::from)?;

        if count == 0 {
            return Err(
                AppError::BadRequest("register a passkey before requiring one".into()).into(),
            );
        }
    }

    let new_token_version = user.0.token_version + 1;

    sqlx::query("UPDATE users SET passkey_required = $1, token_version = $2 WHERE id = $3")
        .bind(body.required)
        .bind(new_token_version)
        .bind(&user.0.id)
        .execute(&state.db)
        .await
        .map_err(AppError::from)?;

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
