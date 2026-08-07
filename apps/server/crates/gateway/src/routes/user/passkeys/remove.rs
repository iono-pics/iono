use actix_web::{post, web, HttpRequest, HttpResponse};
use iono_core::{
    auth::{refresh, refresh::SessionContext},
    entities::PasskeyCredential,
    web::ApiResult,
    AppError,
};

use crate::{
    auth::JwtUser,
    routes::{
        auth::signed_in_payload,
        user::totp::{require_reauth, ReauthRequest},
    },
    state::AppState,
};

#[utoipa::path(
    post,
    path = "/user/passkeys/{id}/remove",
    request_body = ReauthRequest,
    security(("bearer_auth" = [])),
    params(("id" = String, Path, description = "passkey id")),
    responses(
        (status = 200, description = "passkey removed, other sessions ended, returns a fresh token pair"),
        (status = 400, description = "validation failed, or removing the last passkey while passkeys are required"),
        (status = 401, description = "missing/invalid token or failed authentication"),
        (status = 404, description = "no such passkey")
    )
)]
#[post("/passkeys/{id}/remove")]
pub async fn remove_passkey(
    req: HttpRequest,
    state: web::Data<AppState>,
    user: JwtUser,
    path: web::Path<String>,
    body: web::Json<ReauthRequest>,
) -> ApiResult<HttpResponse> {
    require_reauth(&user.0, &body).await?;

    let passkey_id = path.into_inner();

    let existing = sqlx::query_as::<_, PasskeyCredential>(
        "SELECT * FROM passkeys WHERE id = $1 AND user_id = $2",
    )
    .bind(&passkey_id)
    .bind(&user.0.id)
    .fetch_optional(&state.db)
    .await
    .map_err(AppError::from)?
    .ok_or(AppError::NotFound)?;

    if user.0.passkey_required {
        let remaining: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM passkeys WHERE user_id = $1 AND id != $2")
                .bind(&user.0.id)
                .bind(&existing.id)
                .fetch_one(&state.db)
                .await
                .map_err(AppError::from)?;

        if remaining == 0 {
            return Err(AppError::BadRequest(
                "cannot remove the last passkey while passkeys are required".into(),
            )
            .into());
        }
    }

    let new_token_version = user.0.token_version + 1;

    let mut tx = state.db.begin().await.map_err(AppError::from)?;

    sqlx::query("DELETE FROM passkeys WHERE id = $1")
        .bind(&existing.id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::from)?;

    sqlx::query("UPDATE users SET token_version = $1 WHERE id = $2")
        .bind(new_token_version)
        .bind(&user.0.id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::from)?;

    refresh::revoke_all_for_user(&mut *tx, &user.0.id).await?;

    tx.commit().await.map_err(AppError::from)?;

    let payload = signed_in_payload(
        &state,
        &user.0.id,
        new_token_version,
        &SessionContext::from_request(&req),
    )
    .await?;

    Ok(HttpResponse::Ok().json(payload))
}
