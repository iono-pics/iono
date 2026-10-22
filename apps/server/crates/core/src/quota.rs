use chrono::{Duration, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::entities::Plan;
use crate::error::{AppError, AppResult};

pub async fn plan_for_user<'e, E>(db: E, user_id: &str) -> Result<Plan, AppError>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    sqlx::query_as::<_, Plan>(
        r#"
        SELECT p.* FROM plans p
        INNER JOIN users u
            ON p.id = CASE
                WHEN u.plan_expires_at IS NOT NULL AND u.plan_expires_at <= now()
                    THEN 'free'
                ELSE u.plan_id
            END
        WHERE u.id = $1
        "#,
    )
    .bind(user_id)
    .fetch_optional(db)
    .await?
    .ok_or_else(|| AppError::internal(format!("user {user_id} has no plan (BUG!!!)")))
}

/// stored bytes plus bytes already promised to uploads still in flight, so
/// concurrent uploads cannot each spend the same remaining quota
pub async fn storage_used_bytes<'e, E>(db: E, user_id: &str) -> Result<i64, AppError>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let used: i64 = sqlx::query_scalar(
        r#"
        SELECT (
            (SELECT COALESCE(SUM(size_bytes), 0) FROM files
                WHERE user_id = $1 AND (expires_at IS NULL OR expires_at > now()))
            + (SELECT COALESCE(SUM(octet_length(content)), 0) FROM pastes
                WHERE user_id = $1 AND (expires_at IS NULL OR expires_at > now()))
            + (SELECT COALESCE(SUM(bytes), 0) FROM storage_reservations
                WHERE user_id = $1 AND expires_at > now())
            + (SELECT COALESCE(SUM(size_bytes), 0) FROM upload_sessions
                WHERE user_id = $1 AND expires_at > now())
        )::BIGINT
        "#,
    )
    .bind(user_id)
    .fetch_one(db)
    .await?;

    Ok(used)
}

/// quota decisions for one user happen one at a time while this is held.
/// for callers that record their own claim, like an upload session, in the
/// same transaction
pub async fn lock_user(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: &str,
) -> AppResult<()> {
    sqlx::query("SELECT 1 FROM users WHERE id = $1 FOR UPDATE")
        .bind(user_id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(AppError::Unauthorized)?;
    Ok(())
}

/// quota claimed for bytes on their way in. settle it in the transaction
/// that stores them, so they are never counted twice or not at all. one that
/// is dropped unsettled is released, and one a crash leaves behind expires
pub struct Reservation {
    pub bytes: i64,
    id: String,
    db: PgPool,
    settled: bool,
}

impl Reservation {
    pub async fn settle<'e, E>(mut self, db: E) -> AppResult<()>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        sqlx::query("DELETE FROM storage_reservations WHERE id = $1")
            .bind(&self.id)
            .execute(db)
            .await?;
        self.settled = true;
        Ok(())
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let (db, id) = (self.db.clone(), std::mem::take(&mut self.id));
        runtime.spawn(async move {
            if let Err(e) = sqlx::query("DELETE FROM storage_reservations WHERE id = $1")
                .bind(&id)
                .execute(&db)
                .await
            {
                tracing::warn!(error = %e, "could not release a quota reservation, it will expire");
            }
        });
    }
}

/// `decide` sees the user's plan and usage, in flight uploads included, and
/// returns how many bytes to claim or why not
pub async fn reserve(
    db: &PgPool,
    user_id: &str,
    ttl: Duration,
    decide: impl FnOnce(&Plan, i64) -> AppResult<i64>,
) -> AppResult<Reservation> {
    let mut tx = db.begin().await?;
    lock_user(&mut tx, user_id).await?;
    let plan = plan_for_user(&mut *tx, user_id).await?;
    let used = storage_used_bytes(&mut *tx, user_id).await?;
    let bytes = decide(&plan, used)?;

    let id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO storage_reservations (id, user_id, bytes, expires_at) VALUES ($1, $2, $3, $4)",
    )
    .bind(&id)
    .bind(user_id)
    .bind(bytes)
    .bind(Utc::now() + ttl)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    Ok(Reservation {
        bytes,
        id,
        db: db.clone(),
        settled: false,
    })
}

/// a reservation for a known number of bytes, refused past the quota
pub async fn reserve_bytes(
    db: &PgPool,
    user_id: &str,
    bytes: i64,
    ttl: Duration,
) -> AppResult<Reservation> {
    reserve(db, user_id, ttl, |plan, used| {
        if used + bytes > plan.storage_quota_bytes {
            return Err(AppError::PaymentRequired(
                "storage quota exceeded, consider upgrading your plan.".to_owned(),
            ));
        }
        Ok(bytes)
    })
    .await
}
