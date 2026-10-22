use actix_web::{patch, web, HttpRequest, HttpResponse};
use iono_core::{
    auth::{refresh, refresh::SessionContext},
    web::ApiResult,
    AppError,
};
use serde::Deserialize;
use utoipa::ToSchema;

use crate::{
    auth::JwtUser,
    routes::{
        auth::{registered_passkey_count, signed_in_payload},
        user::totp::{require_reauth, ReauthRequest},
    },
    state::AppState,
};

#[derive(Debug, Deserialize, ToSchema)]
pub struct RequirePasskeyRequest {
    required: bool,
    password: Option<String>,
    totp_code: Option<String>,
}

#[utoipa::path(
    patch,
    path = "/user/passkeys/require",
    request_body = RequirePasskeyRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "passkey requirement updated, other sessions ended, returns a fresh token pair"),
        (status = 400, description = "validation failed, or enabling requires at least one registered passkey"),
        (status = 401, description = "missing/invalid token or failed authentication")
    )
)]
#[patch("/passkeys/require")]
pub async fn require_passkey(
    req: HttpRequest,
    state: web::Data<AppState>,
    user: JwtUser,
    body: web::Json<RequirePasskeyRequest>,
) -> ApiResult<HttpResponse> {
    let reauth = ReauthRequest::new(body.password.clone(), body.totp_code.clone());
    require_reauth(&state, &user.0, &reauth).await?;

    if body.required && registered_passkey_count(&state.db, &user.0.id).await? == 0 {
        return Err(AppError::BadRequest("register a passkey before requiring one".into()).into());
    }

    let new_token_version = user.0.token_version + 1;

    sqlx::query("UPDATE users SET passkey_required = $1, token_version = $2 WHERE id = $3")
        .bind(body.required)
        .bind(new_token_version)
        .bind(&user.0.id)
        .execute(&state.db)
        .await
        .map_err(AppError::from)?;

    refresh::revoke_all_for_user(&state.db, &user.0.id).await?;

    let payload = signed_in_payload(
        &state,
        &user.0.id,
        new_token_version,
        &SessionContext::from_request(&req),
    )
    .await?;

    Ok(HttpResponse::Ok().json(payload))
}
