use chrono::{Duration, Utc};
use iono_core::AppError;
use serde::{de::DeserializeOwned, Serialize};
use sqlx::{types::Json, FromRow, PgPool};
use uuid::Uuid;

const CEREMONY_TTL_MINUTES: i64 = 5;

#[derive(FromRow)]
struct StoredCeremony {
    user_id: Option<String>,
    state: Json<serde_json::Value>,
}

pub async fn create<T: Serialize>(
    db: &PgPool,
    user_id: Option<&str>,
    purpose: &str,
    state: &T,
) -> Result<String, AppError> {
    let token = Uuid::new_v4().to_string();
    let state = serde_json::to_value(state)
        .map_err(|e| AppError::internal(format!("failed to serialize webauthn state: {e}")))?;

    sqlx::query("DELETE FROM webauthn_ceremonies WHERE expires_at <= now()")
        .execute(db)
        .await
        .map_err(AppError::from)?;

    sqlx::query(
        "INSERT INTO webauthn_ceremonies (id, user_id, purpose, state, expires_at) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(&token)
    .bind(user_id)
    .bind(purpose)
    .bind(Json(state))
    .bind(Utc::now() + Duration::minutes(CEREMONY_TTL_MINUTES))
    .execute(db)
    .await
    .map_err(AppError::from)?;

    Ok(token)
}

pub async fn consume<T: DeserializeOwned>(
    db: &PgPool,
    token: &str,
    purpose: &str,
) -> Result<(Option<String>, T), AppError> {
    let ceremony = sqlx::query_as::<_, StoredCeremony>(
        "DELETE FROM webauthn_ceremonies WHERE id = $1 AND purpose = $2 AND expires_at > now() RETURNING user_id, state",
    )
    .bind(token)
    .bind(purpose)
    .fetch_optional(db)
    .await
    .map_err(AppError::from)?
    .ok_or(AppError::Unauthorized)?;

    let state = serde_json::from_value(ceremony.state.0)
        .map_err(|e| AppError::internal(format!("failed to deserialize webauthn state: {e}")))?;

    Ok((ceremony.user_id, state))
}
