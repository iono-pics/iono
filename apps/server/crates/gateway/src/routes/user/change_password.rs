use actix_web::{post, web, HttpRequest, HttpResponse};
use iono_core::{
    auth::{
        password::{hash_password_async, verify_password_async},
        refresh,
        refresh::SessionContext,
    },
    AppError,
};
use serde::Deserialize;
use utoipa::ToSchema;
use validator::Validate;

use iono_core::web::ApiResult;

use crate::{auth::JwtUser, routes::auth::signed_in_payload, state::AppState};

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct ChangePasswordRequest {
    #[validate(length(max = 256, message = "current password must be at most 256 characters"))]
    current_password: String,
    #[validate(length(min = 8, max = 256, message = "new password must be 8-256 characters"))]
    new_password: String,
}

/// incrementing token_version invalidates every existing access token. the
/// response carries a fresh pair for the calling session
#[utoipa::path(
    post,
    path = "/user/change-password",
    request_body = ChangePasswordRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "password changed, other sessions ended, returns a fresh token pair"),
        (status = 400, description = "validation failed or account has no password set"),
        (status = 401, description = "missing/invalid token or incorrect current password")
    )
)]
#[post("/change-password")]
pub async fn change_password(
    req: HttpRequest,
    state: web::Data<AppState>,
    user: JwtUser,
    body: web::Json<ChangePasswordRequest>,
) -> ApiResult<HttpResponse> {
    body.validate()
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    let Some(current_hash) = user.0.password_hash.clone() else {
        return Err(AppError::BadRequest("account has no password set".into()).into());
    };

    let verified = verify_password_async(body.current_password.clone(), current_hash).await?;
    if !verified {
        return Err(AppError::Unauthorized.into());
    }

    let new_hash = hash_password_async(body.new_password.clone()).await?;
    let new_token_version = user.0.token_version + 1;

    sqlx::query("UPDATE users SET password_hash = $1, token_version = $2 WHERE id = $3")
        .bind(&new_hash)
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
