pub mod discord;
pub mod login;
pub mod passkey_login_finish;
pub mod passkey_login_start;
pub mod restore;
pub mod signup;
pub mod verify_passkey_finish;
pub mod verify_passkey_start;
pub mod verify_totp;

use actix_governor::Governor;
use actix_web::dev::HttpServiceFactory;
use actix_web::web;
use iono_core::{auth::jwt, entities::User, AppError};
use serde_json::{json, Value};
use sqlx::PgPool;

use crate::routes::rate_limit::AuthGovernor;

pub(crate) struct MfaChallenge {
    mfa_token: String,
    methods: Vec<&'static str>,
}

impl MfaChallenge {
    pub(crate) fn json(&self) -> Value {
        json!({
            "mfa_required": true,
            "mfa_token": self.mfa_token,
            "methods": self.methods,
        })
    }

    pub(crate) fn token(&self) -> &str {
        &self.mfa_token
    }

    pub(crate) fn methods(&self) -> &[&'static str] {
        &self.methods
    }
}

pub(crate) async fn mfa_challenge(
    db: &PgPool,
    jwt_secret: &str,
    user: &User,
) -> Result<Option<MfaChallenge>, AppError> {
    if !user.totp_enabled && !user.passkey_required {
        return Ok(None);
    }

    let passkey_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM passkeys WHERE user_id = $1")
        .bind(&user.id)
        .fetch_one(db)
        .await
        .map_err(AppError::from)?;

    let mut methods = Vec::new();
    if passkey_count > 0 {
        methods.push("passkey");
    }
    if user.totp_enabled {
        methods.push("totp");
    }

    Ok(Some(MfaChallenge {
        mfa_token: jwt::issue_mfa_token(&user.id, jwt_secret)?,
        methods,
    }))
}

pub fn scope(governor: &AuthGovernor) -> impl HttpServiceFactory {
    web::scope("/auth")
        .wrap(Governor::new(governor))
        .service(signup::signup)
        .service(login::login)
        .service(verify_totp::verify_login_totp)
        .service(verify_passkey_start::verify_passkey_start)
        .service(verify_passkey_finish::verify_passkey_finish)
        .service(passkey_login_start::passkey_login_start)
        .service(passkey_login_finish::passkey_login_finish)
        .service(restore::restore)
        .service(discord::start::discord_start)
        .service(discord::callback::discord_callback)
        .service(discord::login::discord_login)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "test-secret";

    async fn insert_user(db: &PgPool, totp_enabled: bool, passkey_required: bool) -> User {
        sqlx::query_as::<_, User>(
            r#"
            INSERT INTO users (id, username, email, totp_secret, totp_enabled, passkey_required)
            VALUES ('u1', 'cat', 'cat@iono.test', $1, $2, $3)
            RETURNING *
            "#,
        )
        .bind(totp_enabled.then_some("SECRETSECRET"))
        .bind(totp_enabled)
        .bind(passkey_required)
        .fetch_one(db)
        .await
        .unwrap()
    }

    async fn insert_passkey(db: &PgPool) {
        sqlx::query(
            "INSERT INTO passkeys (id, user_id, credential_id, credential) VALUES ('k1', 'u1', 'cred', '{}'::jsonb)",
        )
        .execute(db)
        .await
        .unwrap();
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn no_challenge_without_mfa(db: PgPool) {
        let user = insert_user(&db, false, false).await;

        assert!(mfa_challenge(&db, SECRET, &user).await.unwrap().is_none());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn totp_account_is_challenged(db: PgPool) {
        let user = insert_user(&db, true, false).await;

        let challenge = mfa_challenge(&db, SECRET, &user)
            .await
            .unwrap()
            .expect("totp account must be challenged");

        assert_eq!(challenge.methods(), ["totp"]);
        let claims = jwt::verify_mfa_token(challenge.token(), SECRET).unwrap();
        assert_eq!(claims.sub, user.id);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn passkey_account_is_challenged(db: PgPool) {
        let user = insert_user(&db, false, true).await;
        insert_passkey(&db).await;

        let challenge = mfa_challenge(&db, SECRET, &user)
            .await
            .unwrap()
            .expect("passkey account must be challenged");

        assert_eq!(challenge.methods(), ["passkey"]);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn both_mfa_methods_are_offered(db: PgPool) {
        let user = insert_user(&db, true, true).await;
        insert_passkey(&db).await;

        let challenge = mfa_challenge(&db, SECRET, &user).await.unwrap().unwrap();

        assert_eq!(challenge.methods(), ["passkey", "totp"]);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn passkey_required_but_none_registered(db: PgPool) {
        let user = insert_user(&db, false, true).await;

        let challenge = mfa_challenge(&db, SECRET, &user)
            .await
            .unwrap()
            .expect("must not fall through to an access token");

        assert!(challenge.methods().is_empty());
    }
}
