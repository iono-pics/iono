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
use webauthn_rs::prelude::{PasskeyAuthentication, PublicKeyCredential};

use crate::{state::AppState, webauthn_sessions};

#[derive(Debug, Deserialize, ToSchema)]
pub struct VerifyPasskeyFinishRequest {
    auth_token: String,
    #[schema(value_type = Object)]
    credential: PublicKeyCredential,
}

#[utoipa::path(
    post,
    path = "/auth/login/verify-passkey/finish",
    request_body = VerifyPasskeyFinishRequest,
    responses(
        (status = 200, description = "returns access token"),
        (status = 401, description = "invalid/expired auth token or webauthn verification failed")
    )
)]
#[post("/login/verify-passkey/finish")]
pub async fn verify_passkey_finish(
    state: web::Data<AppState>,
    body: web::Json<VerifyPasskeyFinishRequest>,
) -> ApiResult<HttpResponse> {
    let (session_user_id, auth_state): (Option<String>, PasskeyAuthentication) =
        webauthn_sessions::consume(&state.db, &body.auth_token, webauthn::PASSKEY_AUTH_PURPOSE)
            .await?;
    let user_id = session_user_id.ok_or(AppError::Unauthorized)?;

    let mut tx = state.db.begin().await.map_err(AppError::from)?;

    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
        .bind(&user_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(AppError::from)?
        .ok_or(AppError::Unauthorized)?;

    let result = webauthn::finish_authentication(&state.webauthn, &body.credential, &auth_state)?;

    let credential_id = webauthn::encode_credential_id(result.cred_id().as_ref());

    let mut passkey = sqlx::query_as::<_, PasskeyCredential>(
        "SELECT * FROM passkeys WHERE credential_id = $1 AND user_id = $2 FOR UPDATE",
    )
    .bind(&credential_id)
    .bind(&user.id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::from)?
    .ok_or(AppError::Unauthorized)?;

    passkey.credential.0.update_credential(&result);

    sqlx::query("UPDATE passkeys SET credential = $1, last_used_at = now() WHERE id = $2")
        .bind(sqlx::types::Json(&passkey.credential.0))
        .bind(&passkey.id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::from)?;

    tx.commit().await.map_err(AppError::from)?;

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
