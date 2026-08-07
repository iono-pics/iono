use actix_web::{http::header, HttpRequest};
use chrono::{DateTime, Duration, Utc};
use rand::Rng;
use sqlx::PgPool;
use uuid::Uuid;

use crate::auth::token::hash_api_token;
use crate::entities::User;
use crate::error::AppError;

pub const REFRESH_TOKEN_PREFIX: &str = "ionor_";

#[derive(Debug, Clone, Default)]
pub struct SessionContext {
    pub user_agent: Option<String>,
    pub ip: Option<String>,
}

const MAX_USER_AGENT_LEN: usize = 256;

impl SessionContext {
    pub fn from_request(req: &HttpRequest) -> Self {
        let user_agent = req
            .headers()
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.chars().take(MAX_USER_AGENT_LEN).collect());

        let ip = req
            .headers()
            .get("cf-connecting-ip")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim().to_string())
            .or_else(|| req.peer_addr().map(|addr| addr.ip().to_string()));

        Self { user_agent, ip }
    }
}

#[derive(Debug, sqlx::FromRow)]
struct RefreshRow {
    id: String,
    user_id: String,
    family_id: String,
    expires_at: DateTime<Utc>,
    rotated_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
}

pub fn generate() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    format!("{REFRESH_TOKEN_PREFIX}{}", hex::encode(bytes))
}

pub async fn issue(
    db: &PgPool,
    user_id: &str,
    ttl_days: i64,
    ctx: &SessionContext,
) -> Result<String, AppError> {
    let family_id = Uuid::new_v4().to_string();
    issue_in_family(db, user_id, &family_id, ttl_days, ctx).await
}

async fn issue_in_family<'e, E>(
    db: E,
    user_id: &str,
    family_id: &str,
    ttl_days: i64,
    ctx: &SessionContext,
) -> Result<String, AppError>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let plaintext = generate();

    sqlx::query(
        r#"
        INSERT INTO refresh_tokens (id, user_id, family_id, token_hash, user_agent, ip, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        "#,
    )
    .bind(Uuid::new_v4().to_string())
    .bind(user_id)
    .bind(family_id)
    .bind(hash_api_token(&plaintext))
    .bind(ctx.user_agent.as_deref())
    .bind(ctx.ip.as_deref())
    .bind(Utc::now() + Duration::days(ttl_days))
    .execute(db)
    .await
    .map_err(AppError::from)?;

    Ok(plaintext)
}

pub async fn rotate(
    db: &PgPool,
    presented: &str,
    ttl_days: i64,
    ctx: &SessionContext,
) -> Result<(User, String), AppError> {
    let hash = hash_api_token(presented);

    let mut tx = db.begin().await.map_err(AppError::from)?;

    let row = sqlx::query_as::<_, RefreshRow>(
        "SELECT * FROM refresh_tokens WHERE token_hash = $1 FOR UPDATE",
    )
    .bind(&hash)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::from)?
    .ok_or(AppError::Unauthorized)?;

    if row.rotated_at.is_some() || row.revoked_at.is_some() {
        sqlx::query(
            "UPDATE refresh_tokens SET revoked_at = now() WHERE family_id = $1 AND revoked_at IS NULL",
        )
        .bind(&row.family_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::from)?;
        tx.commit().await.map_err(AppError::from)?;

        tracing::warn!(
            user_id = %row.user_id,
            family_id = %row.family_id,
            "refresh token replay detected, session revoked"
        );
        return Err(AppError::Unauthorized);
    }

    if row.expires_at <= Utc::now() {
        return Err(AppError::Unauthorized);
    }

    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
        .bind(&row.user_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(AppError::from)?
        .ok_or(AppError::Unauthorized)?;

    if user.deleted_at.is_some() {
        return Err(AppError::Unauthorized);
    }

    sqlx::query("UPDATE refresh_tokens SET rotated_at = now() WHERE id = $1")
        .bind(&row.id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::from)?;

    let next = issue_in_family(&mut *tx, &row.user_id, &row.family_id, ttl_days, ctx).await?;

    tx.commit().await.map_err(AppError::from)?;

    Ok((user, next))
}

pub async fn revoke(db: &PgPool, presented: &str) -> Result<(), AppError> {
    sqlx::query(
        r#"
        UPDATE refresh_tokens SET revoked_at = now()
        WHERE family_id = (SELECT family_id FROM refresh_tokens WHERE token_hash = $1)
          AND revoked_at IS NULL
        "#,
    )
    .bind(hash_api_token(presented))
    .execute(db)
    .await
    .map_err(AppError::from)?;

    Ok(())
}

pub async fn revoke_all_for_user<'e, E>(db: E, user_id: &str) -> Result<u64, AppError>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let revoked = sqlx::query(
        "UPDATE refresh_tokens SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL",
    )
    .bind(user_id)
    .execute(db)
    .await
    .map_err(AppError::from)?
    .rows_affected();

    Ok(revoked)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TTL_DAYS: i64 = 30;

    async fn insert_user(db: &PgPool) -> User {
        sqlx::query_as::<_, User>(
            r#"
            INSERT INTO users (id, username, email)
            VALUES ('u1', 'cat', 'cat@iono.test')
            RETURNING *
            "#,
        )
        .fetch_one(db)
        .await
        .unwrap()
    }

    fn ctx() -> SessionContext {
        SessionContext {
            user_agent: Some("test-agent".into()),
            ip: Some("127.0.0.1".into()),
        }
    }

    #[test]
    fn tokens_carry_the_prefix_and_differ() {
        let a = generate();
        let b = generate();
        assert!(a.starts_with(REFRESH_TOKEN_PREFIX));
        assert_ne!(a, b);
    }

    #[test]
    fn refresh_tokens_are_not_mistaken_for_api_keys() {
        assert!(!generate().starts_with(crate::auth::token::API_KEY_PREFIX));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn rotation_returns_a_new_token(db: PgPool) {
        let user = insert_user(&db).await;
        let first = issue(&db, &user.id, TTL_DAYS, &ctx()).await.unwrap();

        let (rotated_user, second) = rotate(&db, &first, TTL_DAYS, &ctx()).await.unwrap();

        assert_eq!(rotated_user.id, user.id);
        assert_ne!(first, second);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn rotated_tokens_stay_in_one_family(db: PgPool) {
        let user = insert_user(&db).await;
        let first = issue(&db, &user.id, TTL_DAYS, &ctx()).await.unwrap();
        rotate(&db, &first, TTL_DAYS, &ctx()).await.unwrap();

        let families: i64 =
            sqlx::query_scalar("SELECT COUNT(DISTINCT family_id) FROM refresh_tokens")
                .fetch_one(&db)
                .await
                .unwrap();

        assert_eq!(families, 1);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn replaying_a_rotated_token_revokes_the_family(db: PgPool) {
        let user = insert_user(&db).await;
        let first = issue(&db, &user.id, TTL_DAYS, &ctx()).await.unwrap();
        let (_, second) = rotate(&db, &first, TTL_DAYS, &ctx()).await.unwrap();

        let replay = rotate(&db, &first, TTL_DAYS, &ctx()).await;
        assert!(matches!(replay, Err(AppError::Unauthorized)));

        // the successor the attacker did not steal is dead too
        let after = rotate(&db, &second, TTL_DAYS, &ctx()).await;
        assert!(matches!(after, Err(AppError::Unauthorized)));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn unknown_tokens_are_rejected(db: PgPool) {
        insert_user(&db).await;

        let result = rotate(&db, &generate(), TTL_DAYS, &ctx()).await;

        assert!(matches!(result, Err(AppError::Unauthorized)));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn expired_tokens_are_rejected(db: PgPool) {
        let user = insert_user(&db).await;
        let token = issue(&db, &user.id, TTL_DAYS, &ctx()).await.unwrap();

        sqlx::query("UPDATE refresh_tokens SET expires_at = now() - interval '1 second'")
            .execute(&db)
            .await
            .unwrap();

        let result = rotate(&db, &token, TTL_DAYS, &ctx()).await;

        assert!(matches!(result, Err(AppError::Unauthorized)));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn an_expired_token_does_not_revoke_the_family(db: PgPool) {
        let user = insert_user(&db).await;
        let stale = issue(&db, &user.id, TTL_DAYS, &ctx()).await.unwrap();
        sqlx::query("UPDATE refresh_tokens SET expires_at = now() - interval '1 second'")
            .execute(&db)
            .await
            .unwrap();
        let fresh = issue(&db, &user.id, TTL_DAYS, &ctx()).await.unwrap();

        rotate(&db, &stale, TTL_DAYS, &ctx()).await.unwrap_err();

        assert!(rotate(&db, &fresh, TTL_DAYS, &ctx()).await.is_ok());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn deleted_users_cannot_refresh(db: PgPool) {
        let user = insert_user(&db).await;
        let token = issue(&db, &user.id, TTL_DAYS, &ctx()).await.unwrap();

        sqlx::query("UPDATE users SET deleted_at = now() WHERE id = $1")
            .bind(&user.id)
            .execute(&db)
            .await
            .unwrap();

        let result = rotate(&db, &token, TTL_DAYS, &ctx()).await;

        assert!(matches!(result, Err(AppError::Unauthorized)));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn revoke_ends_the_session(db: PgPool) {
        let user = insert_user(&db).await;
        let token = issue(&db, &user.id, TTL_DAYS, &ctx()).await.unwrap();

        revoke(&db, &token).await.unwrap();

        let result = rotate(&db, &token, TTL_DAYS, &ctx()).await;
        assert!(matches!(result, Err(AppError::Unauthorized)));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn revoking_an_unknown_token_is_a_no_op(db: PgPool) {
        let user = insert_user(&db).await;
        let token = issue(&db, &user.id, TTL_DAYS, &ctx()).await.unwrap();

        revoke(&db, &generate()).await.unwrap();

        assert!(rotate(&db, &token, TTL_DAYS, &ctx()).await.is_ok());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn revoke_all_kills_every_session(db: PgPool) {
        let user = insert_user(&db).await;
        let phone = issue(&db, &user.id, TTL_DAYS, &ctx()).await.unwrap();
        let laptop = issue(&db, &user.id, TTL_DAYS, &ctx()).await.unwrap();

        let revoked = revoke_all_for_user(&db, &user.id).await.unwrap();

        assert_eq!(revoked, 2);
        assert!(rotate(&db, &phone, TTL_DAYS, &ctx()).await.is_err());
        assert!(rotate(&db, &laptop, TTL_DAYS, &ctx()).await.is_err());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn revoking_one_session_leaves_the_others(db: PgPool) {
        let user = insert_user(&db).await;
        let phone = issue(&db, &user.id, TTL_DAYS, &ctx()).await.unwrap();
        let laptop = issue(&db, &user.id, TTL_DAYS, &ctx()).await.unwrap();

        revoke(&db, &phone).await.unwrap();

        assert!(rotate(&db, &phone, TTL_DAYS, &ctx()).await.is_err());
        assert!(rotate(&db, &laptop, TTL_DAYS, &ctx()).await.is_ok());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn session_context_is_recorded(db: PgPool) {
        let user = insert_user(&db).await;
        issue(&db, &user.id, TTL_DAYS, &ctx()).await.unwrap();

        let (agent, ip): (Option<String>, Option<String>) =
            sqlx::query_as("SELECT user_agent, ip FROM refresh_tokens")
                .fetch_one(&db)
                .await
                .unwrap();

        assert_eq!(agent.as_deref(), Some("test-agent"));
        assert_eq!(ip.as_deref(), Some("127.0.0.1"));
    }
}
