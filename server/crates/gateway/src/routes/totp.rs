use actix_web::{post, web, HttpResponse};
use iono_core::{
    auth::{
        jwt,
        password::{hash_password_async, verify_password_async},
        token, totp,
    },
    entities::{TotpRecoveryCode, User},
    AppError,
};
use secrecy::ExposeSecret;
use serde::Deserialize;
use utoipa::ToSchema;
use uuid::Uuid;
use validator::Validate;

use iono_core::web::ApiResult;

use crate::{auth::JwtUser, state::AppState};

const RECOVERY_CODE_COUNT: usize = 10;

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct ConfirmTotpRequest {
    #[validate(length(equal = 6, message = "code must be 6 digits"))]
    code: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ReauthRequest {
    password: Option<String>,
    totp_code: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct VerifyLoginTotpRequest {
    mfa_token: String,
    code: Option<String>,
    recovery_code: Option<String>,
}

/// requires exactly one of password/totp_code, verifying whichever was provided
async fn require_reauth(user: &User, req: &ReauthRequest) -> Result<(), AppError> {
    match (&req.password, &req.totp_code) {
        (Some(password), None) => {
            let Some(hash) = user.password_hash.clone() else {
                return Err(AppError::BadRequest("account has no password set".into()));
            };
            if !verify_password_async(password.clone(), hash).await? {
                return Err(AppError::Unauthorized);
            }
            Ok(())
        }
        (None, Some(code)) => {
            let Some(secret) = user.totp_secret.clone() else {
                return Err(AppError::BadRequest("totp is not enabled".into()));
            };
            if !totp::verify_totp_code(&secret, code)? {
                return Err(AppError::Unauthorized);
            }
            Ok(())
        }
        _ => Err(AppError::BadRequest("provide password or totp code".into())),
    }
}

async fn replace_recovery_codes(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: &str,
) -> Result<Vec<String>, AppError> {
    sqlx::query("DELETE FROM totp_recovery_codes WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut **tx)
        .await
        .map_err(AppError::from)?;

    let mut codes = Vec::with_capacity(RECOVERY_CODE_COUNT);
    for _ in 0..RECOVERY_CODE_COUNT {
        let code = token::generate_recovery_code();
        let code_hash = hash_password_async(code.clone()).await?;

        sqlx::query("INSERT INTO totp_recovery_codes (id, user_id, code_hash) VALUES ($1, $2, $3)")
            .bind(Uuid::new_v4().to_string())
            .bind(user_id)
            .bind(&code_hash)
            .execute(&mut **tx)
            .await
            .map_err(AppError::from)?;

        codes.push(code);
    }

    Ok(codes)
}

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
