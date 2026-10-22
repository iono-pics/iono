use actix_web::{post, web, HttpRequest, HttpResponse};
use iono_core::{
    auth::{refresh, refresh::SessionContext},
    web::ApiResult,
    AppError,
};

use crate::{auth::JwtUser, routes::auth::signed_in_payload, state::AppState};

use super::{replace_recovery_codes, require_reauth, ReauthRequest};

#[utoipa::path(
    post,
    path = "/user/totp/recovery-codes/regenerate",
    request_body = ReauthRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "returns new recovery codes and a fresh token pair; other sessions are ended"),
        (status = 400, description = "validation failed"),
        (status = 401, description = "missing/invalid token or failed authentication")
    )
)]
#[post("/totp/recovery-codes/regenerate")]
pub async fn regenerate_recovery_codes(
    req: HttpRequest,
    state: web::Data<AppState>,
    user: JwtUser,
    body: web::Json<ReauthRequest>,
) -> ApiResult<HttpResponse> {
    require_reauth(&state, &user.0, &body).await?;

    let new_token_version = user.0.token_version + 1;

    let mut tx = state.db.begin().await.map_err(AppError::from)?;

    let recovery_codes =
        replace_recovery_codes(&mut tx, &user.0.id, state.config.totp_recovery_code_count).await?;

    sqlx::query("UPDATE users SET token_version = $1 WHERE id = $2")
        .bind(new_token_version)
        .bind(&user.0.id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::from)?;

    refresh::revoke_all_for_user(&mut *tx, &user.0.id).await?;

    tx.commit().await.map_err(AppError::from)?;

    let mut payload = signed_in_payload(
        &state,
        &user.0.id,
        new_token_version,
        &SessionContext::from_request(&req),
    )
    .await?;
    payload["recovery_codes"] = recovery_codes.into();

    Ok(HttpResponse::Ok().json(payload))
}
