use sqlx::PgPool;

use crate::entities::Plan;
use crate::error::AppError;

pub async fn plan_for_user(pool: &PgPool, user_id: &str) -> Result<Plan, AppError> {
    sqlx::query_as::<_, Plan>(
        r#"
        SELECT p.* FROM plans p
        INNER JOIN users u ON u.plan_id = p.id
        WHERE u.id = $1
        "#,
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| AppError::internal(format!("user {user_id} has no plan (BUG!!!)")))
}

pub async fn storage_used_bytes(pool: &PgPool, user_id: &str) -> Result<i64, AppError> {
    let used: Option<i64> = sqlx::query_scalar(
        r#"
        SELECT SUM(size_bytes)::bigint FROM files
        WHERE user_id = $1 AND (expires_at IS NULL OR expires_at > now())
        "#,
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    Ok(used.unwrap_or(0)) // TODO: handle this better
}

pub async fn check_before_upload(
    pool: &PgPool,
    user_id: &str,
    additional_bytes: i64,
) -> Result<(), AppError> {
    let plan = plan_for_user(pool, user_id).await?;

    if additional_bytes > plan.max_upload_bytes {
        return Err(AppError::PaymentRequired(
            "file is too large, consider upgrading your plan.".to_owned(),
        ));
    }

    let used = storage_used_bytes(pool, user_id).await?;
    if used + additional_bytes > plan.storage_quota_bytes {
        return Err(AppError::PaymentRequired(
            "storage quota exceeded, consider upgrading your plan.".to_owned(),
        ));
    }

    Ok(())
}
