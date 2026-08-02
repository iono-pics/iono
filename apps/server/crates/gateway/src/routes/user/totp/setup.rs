use actix_web::{post, web, HttpResponse};
use iono_core::{auth::totp, web::ApiResult, AppError};

use crate::{auth::JwtUser, state::AppState};

#[utoipa::path(
    post,
    path = "/user/totp/setup",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "returns a new totp secret and otpauth url to scan"),
        (status = 401, description = "missing or invalid token"),
        (status = 409, description = "totp is already enabled")
    )
)]
#[post("/totp/setup")]
pub async fn setup_totp(state: web::Data<AppState>, user: JwtUser) -> ApiResult<HttpResponse> {
    if user.0.totp_enabled {
        return Err(AppError::Conflict("totp is already enabled".into()).into());
    }

    let setup = totp::generate_totp_setup(&user.0.email)?;

    sqlx::query("UPDATE users SET totp_secret = $1 WHERE id = $2")
        .bind(&setup.secret_base32)
        .bind(&user.0.id)
        .execute(&state.db)
        .await
        .map_err(AppError::from)?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "secret_base32": setup.secret_base32,
        "otpauth_url": setup.otpauth_url,
    })))
}
