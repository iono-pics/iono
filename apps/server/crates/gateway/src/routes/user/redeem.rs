use actix_web::{post, web, HttpResponse};
use chrono::{DateTime, Utc};
use iono_core::{
    web::{ApiResult, MapDbError, OptionExt},
    AppError,
};
use serde::Deserialize;
use serde_json::json;
use utoipa::ToSchema;

use crate::{auth::JwtUser, state::AppState};

#[derive(Debug, Deserialize, ToSchema)]
pub struct RedeemRequest {
    code: String,
}

#[utoipa::path(
    post,
    path = "/user/redeem",
    request_body = RedeemRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "code redeemed; plan applied"),
        (status = 400, description = "empty code"),
        (status = 401, description = "missing or invalid token"),
        (status = 404, description = "no such code, or already redeemed, or expired"),
    )
)]
#[post("/redeem")]
pub async fn redeem_code(
    state: web::Data<AppState>,
    user: JwtUser,
    body: web::Json<RedeemRequest>,
) -> ApiResult<HttpResponse> {
    let code = body.into_inner().code.trim().to_string();
    if code.is_empty() {
        return Err(AppError::BadRequest("code must not be empty".into()).into());
    }

    let mut tx = state.db.begin().await.map_err(AppError::from)?;

    let (plan_id, duration_days): (String, Option<i32>) = sqlx::query_as(
        r#"
        UPDATE redemption_codes
        SET redeemed_by = $1, redeemed_at = now()
        WHERE code = $2
          AND redeemed_by IS NULL
          AND (expires_at IS NULL OR expires_at > now())
        RETURNING plan_id, duration_days
        "#,
    )
    .bind(&user.0.id)
    .bind(&code)
    .fetch_optional(&mut *tx)
    .await
    .map_err(MapDbError::new().build())?
    .ok_or_not_found()?;

    let (new_plan_id, plan_expires_at): (String, Option<DateTime<Utc>>) = sqlx::query_as(
        r#"
        UPDATE users SET
            plan_id = $1,
            plan_expires_at = CASE
                WHEN $2::int IS NULL THEN NULL
                WHEN plan_id = $1 AND plan_expires_at IS NULL THEN NULL
                WHEN plan_id = $1 THEN GREATEST(
                    plan_expires_at,
                    now() + make_interval(days => $2)
                )
                ELSE now() + make_interval(days => $2)
            END
        WHERE id = $3
        RETURNING plan_id, plan_expires_at
        "#,
    )
    .bind(&plan_id)
    .bind(duration_days)
    .bind(&user.0.id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::from)?;

    tx.commit().await.map_err(AppError::from)?;

    Ok(HttpResponse::Ok().json(json!({
        "plan_id": new_plan_id,
        "plan_expires_at": plan_expires_at,
    })))
}
