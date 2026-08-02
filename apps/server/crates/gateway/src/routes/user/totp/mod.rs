pub mod confirm;
pub mod disable;
pub mod recovery_codes;
pub mod setup;

use iono_core::{
    auth::{
        password::{hash_password_async, verify_password_async},
        token, totp,
    },
    entities::User,
    AppError,
};
use serde::Deserialize;
use utoipa::ToSchema;
use uuid::Uuid;

const RECOVERY_CODE_COUNT: usize = 10;

#[derive(Debug, Deserialize, ToSchema)]
pub struct ReauthRequest {
    password: Option<String>,
    totp_code: Option<String>,
}

pub(crate) async fn require_reauth(user: &User, req: &ReauthRequest) -> Result<(), AppError> {
    match (&req.password, &req.totp_code) {
        (Some(password), None) => {
            let Some(hash) = user.password_hash.clone() else {
                return Err(AppError::BadRequest("account has no password set".into()));
            };
            if !verify_password_async(password.clone(), hash).await? {
                return Err(AppError::Unauthorized);
            }
            Ok(())
        }
        (None, Some(code)) => {
            let Some(secret) = user.totp_secret.clone() else {
                return Err(AppError::BadRequest("totp is not enabled".into()));
            };
            if !totp::verify_totp_code(&secret, code)? {
                return Err(AppError::Unauthorized);
            }
            Ok(())
        }
        _ => Err(AppError::BadRequest("provide password or totp code".into())),
    }
}

async fn replace_recovery_codes(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: &str,
) -> Result<Vec<String>, AppError> {
    sqlx::query("DELETE FROM totp_recovery_codes WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut **tx)
        .await
        .map_err(AppError::from)?;

    let mut codes = Vec::with_capacity(RECOVERY_CODE_COUNT);
    for _ in 0..RECOVERY_CODE_COUNT {
        let code = token::generate_recovery_code();
        let code_hash = hash_password_async(code.clone()).await?;

        sqlx::query("INSERT INTO totp_recovery_codes (id, user_id, code_hash) VALUES ($1, $2, $3)")
            .bind(Uuid::new_v4().to_string())
            .bind(user_id)
            .bind(&code_hash)
            .execute(&mut **tx)
            .await
            .map_err(AppError::from)?;

        codes.push(code);
    }

    Ok(codes)
}
