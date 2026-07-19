use actix_web::{post, web, HttpResponse};
use iono_core::{auth::webauthn, entities::PasskeyCredential, web::ApiResult, AppError};
use uuid::Uuid;

use crate::{auth::JwtUser, state::AppState, webauthn_sessions};

#[utoipa::path(
    post,
    path = "/user/passkeys/register/start",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "returns a webauthn registration challenge"),
        (status = 401, description = "missing or invalid token")
    )
)]
#[post("/passkeys/register/start")]
pub async fn register_start(state: web::Data<AppState>, user: JwtUser) -> ApiResult<HttpResponse> {
    let existing =
        sqlx::query_as::<_, PasskeyCredential>("SELECT * FROM passkeys WHERE user_id = $1")
            .bind(&user.0.id)
            .fetch_all(&state.db)
            .await
            .map_err(AppError::from)?;

    let exclude_credentials = existing
        .iter()
        .map(|p| p.credential.0.cred_id().clone())
        .collect();

    let user_id = Uuid::parse_str(&user.0.id)
        .map_err(|e| AppError::internal(format!("user id is not a valid uuid: {e}")))?;

    let (challenge, reg_state) = webauthn::start_registration(
        &state.webauthn,
        user_id,
        &user.0.username,
        &user.0.username,
        exclude_credentials,
    )?;

    let registration_token = webauthn_sessions::create(
        &state.db,
        Some(&user.0.id),
        webauthn::PASSKEY_REG_PURPOSE,
        &reg_state,
    )
    .await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "challenge": challenge,
        "registration_token": registration_token,
    })))
}
