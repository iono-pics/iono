pub mod callback;
pub mod login;
pub mod start;

use chrono::{DateTime, Duration, Utc};
use iono_core::{
    auth::{jwt, token},
    entities::User,
    oauth::{fetch_discord_user, DiscordUser, OAuthClient, OAuthError, Tokens},
    AppError,
};
use rand::RngExt;
use serde::Serialize;
use sqlx::PgPool;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{
    routes::auth::{mfa_challenge, MfaChallenge},
    state::AppState,
};

const PROVIDER: &str = "discord";
const FLOW_STATE_TTL_MINUTES: i64 = 15;

#[derive(Debug, Serialize, ToSchema)]
pub struct DiscordAuthResponse {
    pub access_token: String,
    pub is_new_user: bool,
}

pub(crate) fn require_configured(client: &OAuthClient) -> Result<(), AppError> {
    if !client.is_configured() {
        return Err(AppError::internal("discord oauth is not configured"));
    }
    Ok(())
}

pub(crate) fn map_oauth_error(err: OAuthError) -> AppError {
    match err {
        OAuthError::NotConfigured => AppError::internal("discord oauth is not configured"),
        OAuthError::Http { status, .. } if (400..500).contains(&status) => AppError::Unauthorized,
        OAuthError::Exchange(_) => AppError::Unauthorized,
        other => AppError::internal_from("discord oauth call failed", other),
    }
}

pub(crate) async fn consume_flow_and_fetch(
    state: &AppState,
    csrf_token: &str,
    code: &str,
) -> Result<(Tokens, DiscordUser, Option<String>), AppError> {
    require_configured(&state.discord)?;

    let row: Option<(String, Option<String>)> = sqlx::query_as(
        r#"
        DELETE FROM oauth_flow_states
        WHERE id = $1 AND provider = $2 AND expires_at > now()
        RETURNING pkce_verifier, link_user_id
        "#,
    )
    .bind(csrf_token)
    .bind(PROVIDER)
    .fetch_optional(&state.db)
    .await
    .map_err(AppError::from)?;

    let (verifier, link_user_id) = row.ok_or(AppError::Unauthorized)?;

    let tokens = state
        .discord
        .exchange_code(code, &verifier)
        .await
        .map_err(map_oauth_error)?;
    let discord_user = fetch_discord_user(state.discord.http(), &tokens.access_token)
        .await
        .map_err(map_oauth_error)?;

    Ok((tokens, discord_user, link_user_id))
}

pub(crate) enum LoginOutcome {
    SignedIn {
        access_token: String,
        is_new_user: bool,
    },
    MfaRequired(MfaChallenge),
}

pub(crate) async fn login_or_signup(
    db: &PgPool,
    jwt_secret: &str,
    access_ttl_minutes: i64,
    tokens: &Tokens,
    discord_user: &DiscordUser,
) -> Result<LoginOutcome, AppError> {
    let expires_at = tokens.expires_in.map(|s| Utc::now() + Duration::seconds(s));

    let existing: Option<(String,)> = sqlx::query_as(
        "SELECT user_id FROM oauth_accounts WHERE provider = $1 AND provider_user_id = $2",
    )
    .bind(PROVIDER)
    .bind(&discord_user.id)
    .fetch_optional(db)
    .await
    .map_err(AppError::from)?;

    if let Some((user_id,)) = existing {
        let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
            .bind(&user_id)
            .fetch_optional(db)
            .await
            .map_err(AppError::from)?
            .ok_or(AppError::Unauthorized)?;

        if user.deleted_at.is_some() {
            return Err(AppError::Unauthorized);
        }

        sqlx::query(
            r#"
            UPDATE oauth_accounts SET
                access_token  = $1,
                refresh_token = $2,
                expires_at    = $3
            WHERE provider = $4 AND provider_user_id = $5
            "#,
        )
        .bind(&tokens.access_token)
        .bind(&tokens.refresh_token)
        .bind(expires_at)
        .bind(PROVIDER)
        .bind(&discord_user.id)
        .execute(db)
        .await
        .map_err(AppError::from)?;

        if let Some(challenge) = mfa_challenge(db, jwt_secret, &user).await? {
            return Ok(LoginOutcome::MfaRequired(challenge));
        }

        let access_token =
            jwt::issue_access_token(&user.id, user.token_version, jwt_secret, access_ttl_minutes)?;
        return Ok(LoginOutcome::SignedIn {
            access_token,
            is_new_user: false,
        });
    }

    let user = create_user_from_discord(db, discord_user).await?;
    insert_oauth_account(
        db,
        &user.id,
        &discord_user.id,
        &tokens.access_token,
        tokens.refresh_token.as_deref(),
        expires_at,
    )
    .await?;

    let access_token =
        jwt::issue_access_token(&user.id, user.token_version, jwt_secret, access_ttl_minutes)?;
    Ok(LoginOutcome::SignedIn {
        access_token,
        is_new_user: true,
    })
}

pub(crate) async fn link_to_user(
    state: &AppState,
    user_id: &str,
    tokens: &Tokens,
    discord_user: &DiscordUser,
) -> Result<(), AppError> {
    let existing_owner: Option<(String,)> = sqlx::query_as(
        "SELECT user_id FROM oauth_accounts WHERE provider = $1 AND provider_user_id = $2",
    )
    .bind(PROVIDER)
    .bind(&discord_user.id)
    .fetch_optional(&state.db)
    .await
    .map_err(AppError::from)?;

    if let Some((owner,)) = existing_owner {
        if owner == user_id {
            return Ok(());
        }
        return Err(AppError::Conflict(
            "that discord account is already linked to another user".into(),
        ));
    }

    let expires_at = tokens.expires_in.map(|s| Utc::now() + Duration::seconds(s));

    insert_oauth_account(
        &state.db,
        user_id,
        &discord_user.id,
        &tokens.access_token,
        tokens.refresh_token.as_deref(),
        expires_at,
    )
    .await
    .map_err(|e| match e {
        AppError::Database(db_err) => match &db_err {
            sqlx::Error::Database(inner)
                if inner.kind() == sqlx::error::ErrorKind::UniqueViolation =>
            {
                AppError::Conflict("your account already has a linked discord".into())
            }
            _ => AppError::Database(db_err),
        },
        other => other,
    })
}

pub(crate) async fn store_flow_state(
    db: &PgPool,
    csrf_token: &str,
    pkce_verifier: &str,
    link_user_id: Option<&str>,
) -> Result<(), AppError> {
    let expires_at = Utc::now() + Duration::minutes(FLOW_STATE_TTL_MINUTES);
    sqlx::query(
        r#"
        INSERT INTO oauth_flow_states (id, provider, pkce_verifier, link_user_id, expires_at)
        VALUES ($1, $2, $3, $4, $5)
        "#,
    )
    .bind(csrf_token)
    .bind(PROVIDER)
    .bind(pkce_verifier)
    .bind(link_user_id)
    .bind(expires_at)
    .execute(db)
    .await
    .map_err(AppError::from)?;
    Ok(())
}

async fn insert_oauth_account(
    db: &PgPool,
    user_id: &str,
    provider_user_id: &str,
    access_token: &str,
    refresh_token: Option<&str>,
    expires_at: Option<DateTime<Utc>>,
) -> Result<(), AppError> {
    let id = Uuid::new_v4().to_string();
    sqlx::query(
        r#"
        INSERT INTO oauth_accounts
            (id, user_id, provider, provider_user_id, access_token, refresh_token, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(PROVIDER)
    .bind(provider_user_id)
    .bind(access_token)
    .bind(refresh_token)
    .bind(expires_at)
    .execute(db)
    .await
    .map_err(AppError::from)?;
    Ok(())
}

async fn create_user_from_discord(
    db: &PgPool,
    discord_user: &DiscordUser,
) -> Result<User, AppError> {
    let base_username = sanitize_username(&discord_user.username);
    let email = discord_user
        .email
        .as_deref()
        .filter(|_| discord_user.verified.unwrap_or(false));

    for attempt in 0..5 {
        let username = if attempt == 0 {
            base_username.clone()
        } else {
            let suffix: u32 = rand::rng().random_range(1000..=999_999);
            let mut candidate = format!("{base_username}_{suffix}");
            if candidate.len() > 32 {
                candidate.truncate(32);
            }
            candidate
        };

        let id = Uuid::new_v4().to_string();
        let result = sqlx::query_as::<_, User>(
            "INSERT INTO users (id, username, email, password_hash) VALUES ($1, $2, $3, NULL) RETURNING *",
        )
        .bind(&id)
        .bind(&username)
        .bind(email)
        .fetch_one(db)
        .await;

        match result {
            Ok(user) => {
                seed_default_api_key(db, &user.id).await?;
                return Ok(user);
            }
            Err(sqlx::Error::Database(db_err))
                if db_err.kind() == sqlx::error::ErrorKind::UniqueViolation =>
            {
                if let Some(constraint) = db_err.constraint() {
                    if constraint.contains("email") {
                        return Err(AppError::Conflict(
                            "an account already exists with that email".into(),
                        ));
                    }
                }
                continue;
            }
            Err(e) => return Err(AppError::from(e)),
        }
    }

    Err(AppError::internal(
        "could not generate a unique username from discord account",
    ))
}

async fn seed_default_api_key(db: &PgPool, user_id: &str) -> Result<(), AppError> {
    let api_token = token::generate_api_token();
    let api_token_hash = token::hash_api_token(&api_token);
    let api_key_id = Uuid::new_v4().to_string();

    sqlx::query(
        "INSERT INTO api_keys (id, user_id, token_hash, token_prefix, name) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(&api_key_id)
    .bind(user_id)
    .bind(&api_token_hash)
    .bind(&api_token[..13])
    .bind("default")
    .execute(db)
    .await
    .map_err(AppError::from)?;
    Ok(())
}

fn sanitize_username(raw: &str) -> String {
    let mut cleaned: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();

    if cleaned.len() > 32 {
        cleaned.truncate(32);
    }
    while cleaned.len() < 3 {
        cleaned.push('_');
    }
    cleaned
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "test-secret";
    const TTL: i64 = 15;

    fn tokens() -> Tokens {
        Tokens {
            access_token: "discord-access".into(),
            refresh_token: None,
            expires_in: None,
        }
    }

    fn discord_user() -> DiscordUser {
        DiscordUser {
            id: "discord-1".into(),
            username: "cat".into(),
            email: None,
            verified: None,
            avatar: None,
            global_name: None,
        }
    }

    async fn seed_linked_user(db: &PgPool, totp_enabled: bool) {
        sqlx::query(
            r#"
            INSERT INTO users (id, username, email, totp_secret, totp_enabled)
            VALUES ('u1', 'cat', 'cat@iono.test', $1, $2)
            "#,
        )
        .bind(totp_enabled.then_some("SECRETSECRET"))
        .bind(totp_enabled)
        .execute(db)
        .await
        .unwrap();

        sqlx::query(
            r#"
            INSERT INTO oauth_accounts (id, user_id, provider, provider_user_id)
            VALUES ('o1', 'u1', 'discord', 'discord-1')
            "#,
        )
        .execute(db)
        .await
        .unwrap();
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn linked_account_with_totp_is_challenged(db: PgPool) {
        seed_linked_user(&db, true).await;

        let outcome = login_or_signup(&db, SECRET, TTL, &tokens(), &discord_user())
            .await
            .unwrap();

        match outcome {
            LoginOutcome::MfaRequired(challenge) => assert_eq!(challenge.methods(), ["totp"]),
            LoginOutcome::SignedIn { .. } => panic!("discord login bypassed mfa"),
        }
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn linked_account_without_mfa_signs_in(db: PgPool) {
        seed_linked_user(&db, false).await;

        let outcome = login_or_signup(&db, SECRET, TTL, &tokens(), &discord_user())
            .await
            .unwrap();

        match outcome {
            LoginOutcome::SignedIn { is_new_user, .. } => assert!(!is_new_user),
            LoginOutcome::MfaRequired(_) => panic!("account has no mfa"),
        }
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn unknown_discord_account_creates_a_user(db: PgPool) {
        let outcome = login_or_signup(&db, SECRET, TTL, &tokens(), &discord_user())
            .await
            .unwrap();

        match outcome {
            LoginOutcome::SignedIn { is_new_user, .. } => assert!(is_new_user),
            LoginOutcome::MfaRequired(_) => panic!("a new account has no mfa"),
        }
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn deleted_user_cannot_sign_in(db: PgPool) {
        seed_linked_user(&db, false).await;
        sqlx::query("UPDATE users SET deleted_at = now() WHERE id = 'u1'")
            .execute(&db)
            .await
            .unwrap();

        let result = login_or_signup(&db, SECRET, TTL, &tokens(), &discord_user()).await;

        assert!(matches!(result, Err(AppError::Unauthorized)));
    }
}
