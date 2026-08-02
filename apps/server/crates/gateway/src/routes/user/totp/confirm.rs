use actix_web::{post, web, HttpResponse};
use iono_core::{auth::totp, web::ApiResult, AppError};
use serde::Deserialize;
use utoipa::ToSchema;
use validator::Validate;

use crate::{auth::JwtUser, state::AppState};

use super::replace_recovery_codes;

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct ConfirmTotpRequest {
    #[validate(length(equal = 6, message = "code must be 6 digits"))]
    code: String,
}

#[utoipa::path(
    post,
    path = "/user/totp/confirm",
    request_body = ConfirmTotpRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "totp enabled and returns recovery codes"),
        (status = 400, description = "validation failed"),
        (status = 401, description = "missing/invalid token or incorrect code")
    )
)]
#[post("/totp/confirm")]
pub async fn confirm_totp(
    state: web::Data<AppState>,
    user: JwtUser,
    body: web::Json<ConfirmTotpRequest>,
) -> ApiResult<HttpResponse> {
    body.validate()
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    let Some(secret) = user.0.totp_secret.clone() else {
        return Err(AppError::BadRequest("totp setup has not been started".into()).into());
    };

    if !totp::verify_totp_code(&secret, &body.code)? {
        return Err(AppError::Unauthorized.into());
    }

    let mut tx = state.db.begin().await.map_err(AppError::from)?;

    let recovery_codes = replace_recovery_codes(&mut tx, &user.0.id).await?;

    sqlx::query("UPDATE users SET totp_enabled = true WHERE id = $1")
        .bind(&user.0.id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::from)?;

    tx.commit().await.map_err(AppError::from)?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "recovery_codes": recovery_codes,
    })))
}
