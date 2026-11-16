use actix_web::{post, web, HttpRequest, HttpResponse};
use iono_core::{
    auth::{
        jwt,
        password::{hash_secret, verify_secret},
        refresh::SessionContext,
        totp,
    },
    entities::{TotpRecoveryCode, User},
    error::AppResult,
    AppError,
};
use secrecy::ExposeSecret;
use serde::Deserialize;
use utoipa::ToSchema;

use iono_core::web::ApiResult;

use crate::{
    routes::auth::{registered_passkey_count, signed_in_payload},
    state::AppState,
};

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
    req: HttpRequest,
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

    if user.deleted_at.is_some() {
        return Err(AppError::Unauthorized.into());
    }

    if user.passkey_required && registered_passkey_count(&state.db, &user.id).await? > 0 {
        return Err(AppError::BadRequest("a passkey is required for this account".into()).into());
    }

    match (&body.code, &body.recovery_code) {
        (Some(code), None) => {
            let Some(secret) = user.totp_secret.clone() else {
                return Err(AppError::Unauthorized.into());
            };
            if !totp::accept_code(&state.db, &state.keyring, &user.id, &secret, code).await? {
                return Err(AppError::Unauthorized.into());
            }
        }
        (None, Some(recovery_code)) => {
            // recovery codes share the totp lockout, so they are no way around it
            totp::ensure_not_locked(&state.db, &user.id).await?;
            if !consume_recovery_code(&state, &user.id, recovery_code).await? {
                totp::record_failure(&state.db, &user.id).await?;
                return Err(AppError::Unauthorized.into());
            }
            totp::record_success(&state.db, &user.id).await?;
        }
        _ => {
            return Err(AppError::BadRequest("provide code or recovery code".into()).into());
        }
    }

    let payload = signed_in_payload(
        &state,
        &user.id,
        user.token_version,
        &SessionContext::from_request(&req),
    )
    .await?;

    Ok(HttpResponse::Ok().json(payload))
}

/// marks the code used in the same statement that finds it, so two requests
/// racing with one code cannot both sign in
async fn consume_recovery_code(state: &AppState, user_id: &str, code: &str) -> AppResult<bool> {
    let consumed = sqlx::query_scalar::<_, String>(
        r#"
        UPDATE totp_recovery_codes SET used_at = now()
        WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL
        RETURNING id
        "#,
    )
    .bind(user_id)
    .bind(hash_secret(code))
    .fetch_optional(&state.db)
    .await?;
    if consumed.is_some() {
        return Ok(true);
    }

    // argon2 hashes are salted, so they can only be found by trying each one
    let legacy = sqlx::query_as::<_, TotpRecoveryCode>(
        "SELECT * FROM totp_recovery_codes WHERE user_id = $1 AND used_at IS NULL AND code_hash LIKE '$argon2%'",
    )
    .bind(user_id)
    .fetch_all(&state.db)
    .await?;

    for candidate in legacy {
        if !verify_secret(code, &candidate.code_hash).await?.matched() {
            continue;
        }
        let consumed = sqlx::query(
            "UPDATE totp_recovery_codes SET used_at = now() WHERE id = $1 AND used_at IS NULL",
        )
        .bind(&candidate.id)
        .execute(&state.db)
        .await?
        .rows_affected();
        return Ok(consumed == 1);
    }

    Ok(false)
}
