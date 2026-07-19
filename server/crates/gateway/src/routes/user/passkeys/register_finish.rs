use actix_web::{post, web, HttpResponse};
use iono_core::{auth::webauthn, web::ApiResult, AppError};
use serde::Deserialize;
use utoipa::ToSchema;
use uuid::Uuid;
use webauthn_rs::prelude::{PasskeyRegistration, RegisterPublicKeyCredential};

use crate::{auth::JwtUser, state::AppState, webauthn_sessions};

#[derive(Debug, Deserialize, ToSchema)]
pub struct FinishRegisterPasskeyRequest {
    registration_token: String,
    name: Option<String>,
    #[schema(value_type = Object)]
    credential: RegisterPublicKeyCredential,
}

#[utoipa::path(
    post,
    path = "/user/passkeys/register/finish",
    request_body = FinishRegisterPasskeyRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "passkey registered"),
        (status = 400, description = "webauthn ceremony failed"),
        (status = 401, description = "missing/invalid token, or registration token belongs to a different account")
    )
)]
#[post("/passkeys/register/finish")]
pub async fn register_finish(
    state: web::Data<AppState>,
    user: JwtUser,
    body: web::Json<FinishRegisterPasskeyRequest>,
) -> ApiResult<HttpResponse> {
    let (session_user_id, reg_state): (Option<String>, PasskeyRegistration) =
        webauthn_sessions::consume(
            &state.db,
            &body.registration_token,
            webauthn::PASSKEY_REG_PURPOSE,
        )
        .await?;

    if session_user_id.as_deref() != Some(user.0.id.as_str()) {
        return Err(AppError::Unauthorized.into());
    }

    let passkey = webauthn::finish_registration(&state.webauthn, &body.credential, &reg_state)?;

    let credential_id = webauthn::encode_credential_id(passkey.cred_id().as_ref());
    let id = Uuid::new_v4().to_string();

    sqlx::query(
        "INSERT INTO passkeys (id, user_id, name, credential_id, credential) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(&id)
    .bind(&user.0.id)
    .bind(&body.name)
    .bind(&credential_id)
    .bind(sqlx::types::Json(&passkey))
    .execute(&state.db)
    .await
    .map_err(AppError::from)?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "id": id,
        "name": body.name,
    })))
}
