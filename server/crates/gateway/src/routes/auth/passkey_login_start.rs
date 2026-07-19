use actix_web::{post, web, HttpResponse};
use iono_core::{
    auth::webauthn,
    entities::{PasskeyCredential, User},
    web::ApiResult,
    AppError,
};
use serde::Deserialize;
use utoipa::ToSchema;

use crate::{state::AppState, webauthn_sessions};

#[derive(Debug, Deserialize, ToSchema)]
pub struct PasskeyLoginStartRequest {
    identifier: String,
}

#[utoipa::path(
    post,
    path = "/auth/passkey/login/start",
    request_body = PasskeyLoginStartRequest,
    responses(
        (status = 200, description = "retur1ns a webauthn authentication challenge"), 
        (status = 401, description = "unknown account or no passkeys registered")
    )
)]
#[post("/passkey/login/start")]
pub async fn passkey_login_start(
    state: web::Data<AppState>,
    body: web::Json<PasskeyLoginStartRequest>,
) -> ApiResult<HttpResponse> {
    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE email = $1 OR username = $1")
        .bind(&body.identifier)
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
        return Err(AppError::Unauthorized.into());
    }

    let credentials: Vec<_> = passkeys
        .into_iter()
        .map(|passkey| passkey.credential.0)
        .collect();
    let (challenge, auth_state) = webauthn::start_authentication(&state.webauthn, &credentials)?;

    let session_token = webauthn_sessions::create(
        &state.db,
        Some(&user.id),
        webauthn::PASSKEY_LOGIN_PURPOSE,
        &auth_state,
    )
    .await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "challenge": challenge,
        "session_token": session_token,
    })))
}
