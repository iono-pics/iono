use actix_web::{post, web, HttpResponse};
use iono_core::{
    auth::{jwt, webauthn},
    entities::{PasskeyCredential, User},
    web::ApiResult,
    AppError,
};
use secrecy::ExposeSecret;
use serde::Deserialize;
use utoipa::ToSchema;

use crate::{state::AppState, webauthn_sessions};

#[derive(Debug, Deserialize, ToSchema)]
pub struct VerifyPasskeyStartRequest {
    mfa_token: String,
}

#[utoipa::path(
    post,
    path = "/auth/login/verify-passkey/start",
    request_body = VerifyPasskeyStartRequest,
    responses(
        (status = 200, description = "returns a webauthn authentication challenge"),
        (status = 400, description = "user has no registered passkeys"),
        (status = 401, description = "invalid/expired mfa token")
    )
)]
#[post("/login/verify-passkey/start")]
pub async fn verify_passkey_start(
    state: web::Data<AppState>,
    body: web::Json<VerifyPasskeyStartRequest>,
) -> ApiResult<HttpResponse> {
    let claims = jwt::verify_mfa_token(&body.mfa_token, state.config.jwt_secret.expose_secret())?;

    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
        .bind(&claims.sub)
        .fetch_optional(&state.db)
        .await
        .map_err(AppError::from)?
        .ok_or(AppError::Unauthorized)?;

    let passkeys =
        sqlx::query_as::<_, PasskeyCredential>("SELECT * FROM passkeys WHERE user_id = $1")
            .bind(&user.id)
            .fetch_all(&state.db)
            .await
            .map_err(AppError::from)?;

    if passkeys.is_empty() {
        return Err(AppError::BadRequest("no passkeys registered".into()).into());
    }

    let creds: Vec<_> = passkeys.iter().map(|p| p.credential.0.clone()).collect();

    let (challenge, auth_state) = webauthn::start_authentication(&state.webauthn, &creds)?;

    let auth_token = webauthn_sessions::create(
        &state.db,
        Some(&user.id),
        webauthn::PASSKEY_AUTH_PURPOSE,
        &auth_state,
    )
    .await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "challenge": challenge,
        "auth_token": auth_token,
    })))
}
