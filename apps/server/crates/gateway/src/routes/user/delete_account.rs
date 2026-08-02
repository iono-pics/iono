use actix_web::{delete, web, HttpResponse};
use iono_core::{
    entities::RECOVERY_WINDOW_DAYS,
    web::{ApiResult, MapDbError},
    AppError,
};
use serde_json::json;

use crate::{
    auth::JwtUser,
    routes::user::totp::{require_reauth, ReauthRequest},
    state::AppState,
};

#[utoipa::path(
    delete,
    path = "/user/@me",
    request_body = ReauthRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "account soft-deleted; body reports the recovery deadline"),
        (status = 400, description = "reauth details missing"),
        (status = 401, description = "reauth failed"),
        (status = 409, description = "active subscription — cancel first"),
    )
)]
#[delete("/@me")]
pub async fn delete_account(
    state: web::Data<AppState>,
    user: JwtUser,
    body: web::Json<ReauthRequest>,
) -> ApiResult<HttpResponse> {
    require_reauth(&user.0, &body).await?;

    let active_sub_count: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*) FROM subscriptions
        WHERE user_id = $1
          AND status IN ('trialing', 'active', 'past_due')
        "#,
    )
    .bind(&user.0.id)
    .fetch_one(&state.db)
    .await
    .map_err(AppError::from)?;

    if active_sub_count > 0 {
        return Err(AppError::Conflict(
            "cancel your active subscription before deleting your account".into(),
        )
        .into());
    }

    let user_id = &user.0.id;
    let deleted_at: chrono::DateTime<chrono::Utc> = sqlx::query_scalar(
        r#"
        UPDATE users SET
            deleted_at    = now(),
            token_version = token_version + 1
        WHERE id = $1
        RETURNING deleted_at
        "#,
    )
    .bind(user_id)
    .fetch_one(&state.db)
    .await
    .map_err(MapDbError::new().build())?;

    let recoverable_until = deleted_at + chrono::Duration::days(RECOVERY_WINDOW_DAYS);

    Ok(HttpResponse::Ok().json(json!({
        "status": "pending_deletion",
        "deleted_at": deleted_at,
        "recoverable_until": recoverable_until,
    })))
}
