use actix_web::{post, web, HttpResponse};
use iono_core::{
    auth::{jwt, password::verify_password_async, totp},
    entities::{TotpRecoveryCode, User},
    AppError,
};
use secrecy::ExposeSecret;
use serde::Deserialize;
use utoipa::ToSchema;

use iono_core::web::ApiResult;

use crate::state::AppState;

#[derive(Debug, Deserialize, ToSchema)]
pub struct VerifyLoginTotpRequest {
    mfa_token: String,
    code: Option<String>,
    recovery_code: Option<String>,
}

#[utoipa::path(
    post,
    path = "/auth/login/verify-totp",
    request_body = VerifyLoginTotpRequest,
    responses(
        (status = 200, description = "returns access token"),
        (status = 400, description = "validation failed"),
        (status = 401, description = "invalid/expired mfa token or incorrect code")
    )
)]
#[post("/login/verify-totp")]
pub async fn verify_login_totp(
    state: web::Data<AppState>,
    body: web::Json<VerifyLoginTotpRequest>,
) -> ApiResult<HttpResponse> {
    let claims = jwt::verify_mfa_token(&body.mfa_token, state.config.jwt_secret.expose_secret())?;

    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
        .bind(&claims.sub)
        .fetch_optional(&state.db)
        .await
        .map_err(AppError::from)?
        .ok_or(AppError::Unauthorized)?;

    match (&body.code, &body.recovery_code) {
        (Some(code), None) => {
            let Some(secret) = user.totp_secret.clone() else {
                return Err(AppError::Unauthorized.into());
            };
            if !totp::verify_totp_code(&secret, code)? {
                return Err(AppError::Unauthorized.into());
            }
        }
        (None, Some(recovery_code)) => {
            let candidates = sqlx::query_as::<_, TotpRecoveryCode>(
                "SELECT * FROM totp_recovery_codes WHERE user_id = $1 AND used_at IS NULL",
            )
            .bind(&user.id)
            .fetch_all(&state.db)
            .await
            .map_err(AppError::from)?;

            let mut matched_id = None;
            for candidate in candidates {
                if verify_password_async(recovery_code.clone(), candidate.code_hash.clone()).await?
                {
                    matched_id = Some(candidate.id);
                    break;
                }
            }

            let Some(id) = matched_id else {
                return Err(AppError::Unauthorized.into());
            };

            sqlx::query("UPDATE totp_recovery_codes SET used_at = now() WHERE id = $1")
                .bind(&id)
                .execute(&state.db)
                .await
                .map_err(AppError::from)?;
        }
        _ => {
            return Err(AppError::BadRequest("provide code or recovery code".into()).into());
        }
    }

    let access_token = jwt::issue_access_token(
        &user.id,
        user.token_version,
        state.config.jwt_secret.expose_secret(),
        state.config.jwt_access_ttl_minutes,
    )?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "access_token": access_token,
    })))
}
