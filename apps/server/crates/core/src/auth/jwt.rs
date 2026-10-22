use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use crate::entities::User;
use crate::error::AppError;

// every token kind is signed with the same secret, so each names what it is
// for and every check demands its own. a token can never pass as another kind
const ACCESS_AUDIENCE: &str = "iono:access";
const MFA_AUDIENCE: &str = "iono:mfa";
const RESTORE_AUDIENCE: &str = "iono:restore";

fn validation_for(audience: &str) -> Validation {
    let mut validation = Validation::default();
    validation.set_audience(&[audience]);
    validation.set_required_spec_claims(&["exp", "sub", "aud"]);
    validation
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub aud: String,
    pub iat: usize,
    pub exp: usize,
    pub ver: i32,
}

pub fn issue_access_token(
    user_id: &str,
    token_version: i32,
    secret: &str,
    ttl_minutes: i64,
) -> Result<String, AppError> {
    let now = Utc::now();
    let claims = Claims {
        sub: user_id.to_string(),
        aud: ACCESS_AUDIENCE.to_string(),
        iat: now.timestamp() as usize,
        exp: (now + Duration::minutes(ttl_minutes)).timestamp() as usize,
        ver: token_version,
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| AppError::internal_from("jwt encode failed", e))
}

pub fn verify_access_token(token: &str, secret: &str) -> Result<Claims, AppError> {
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation_for(ACCESS_AUDIENCE),
    )
    .map(|data| data.claims)
    .map_err(|_| AppError::Unauthorized)
}

pub async fn authenticate(db: &PgPool, secret: &str, access_token: &str) -> Result<User, AppError> {
    let claims = verify_access_token(access_token, secret)?;

    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
        .bind(&claims.sub)
        .fetch_optional(db)
        .await
        .map_err(AppError::from)?
        .ok_or(AppError::Unauthorized)?;

    if claims.ver != user.token_version {
        return Err(AppError::Unauthorized);
    }

    if user.deleted_at.is_some() {
        return Err(AppError::Unauthorized);
    }

    Ok(user)
}

const MFA_TOKEN_PURPOSE: &str = "mfa_pending";

#[derive(Debug, Serialize, Deserialize)]
pub struct MfaClaims {
    pub sub: String,
    pub aud: String,
    pub iat: usize,
    pub exp: usize,
    pub purpose: String,
}

pub fn issue_mfa_token(user_id: &str, secret: &str) -> Result<String, AppError> {
    let now = Utc::now();
    let claims = MfaClaims {
        sub: user_id.to_string(),
        aud: MFA_AUDIENCE.to_string(),
        iat: now.timestamp() as usize,
        exp: (now + Duration::minutes(5)).timestamp() as usize,
        purpose: MFA_TOKEN_PURPOSE.to_string(),
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| AppError::internal_from("jwt encode failed", e))
}

pub fn verify_mfa_token(token: &str, secret: &str) -> Result<MfaClaims, AppError> {
    let claims = decode::<MfaClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation_for(MFA_AUDIENCE),
    )
    .map(|data| data.claims)
    .map_err(|_| AppError::Unauthorized)?;

    if claims.purpose != MFA_TOKEN_PURPOSE {
        return Err(AppError::Unauthorized);
    }

    Ok(claims)
}

const RESTORE_TOKEN_PURPOSE: &str = "restore_account";

pub fn issue_restore_token(user_id: &str, secret: &str) -> Result<String, AppError> {
    let now = Utc::now();
    let claims = MfaClaims {
        sub: user_id.to_string(),
        aud: RESTORE_AUDIENCE.to_string(),
        iat: now.timestamp() as usize,
        exp: (now + Duration::minutes(15)).timestamp() as usize,
        purpose: RESTORE_TOKEN_PURPOSE.to_string(),
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| AppError::internal_from("jwt encode failed", e))
}

pub fn verify_restore_token(token: &str, secret: &str) -> Result<MfaClaims, AppError> {
    let claims = decode::<MfaClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation_for(RESTORE_AUDIENCE),
    )
    .map(|data| data.claims)
    .map_err(|_| AppError::Unauthorized)?;

    if claims.purpose != RESTORE_TOKEN_PURPOSE {
        return Err(AppError::Unauthorized);
    }

    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "test-secret";

    #[test]
    fn each_token_verifies_as_its_own_kind() {
        let access = issue_access_token("u1", 3, SECRET, 15).unwrap();
        let claims = verify_access_token(&access, SECRET).unwrap();
        assert_eq!((claims.sub.as_str(), claims.ver), ("u1", 3));

        let mfa = issue_mfa_token("u1", SECRET).unwrap();
        assert_eq!(verify_mfa_token(&mfa, SECRET).unwrap().sub, "u1");

        let restore = issue_restore_token("u1", SECRET).unwrap();
        assert_eq!(verify_restore_token(&restore, SECRET).unwrap().sub, "u1");
    }

    #[test]
    fn no_token_passes_as_another_kind() {
        let access = issue_access_token("u1", 0, SECRET, 15).unwrap();
        let mfa = issue_mfa_token("u1", SECRET).unwrap();
        let restore = issue_restore_token("u1", SECRET).unwrap();

        assert!(verify_mfa_token(&access, SECRET).is_err());
        assert!(verify_restore_token(&access, SECRET).is_err());
        assert!(verify_access_token(&mfa, SECRET).is_err());
        assert!(verify_restore_token(&mfa, SECRET).is_err());
        assert!(verify_access_token(&restore, SECRET).is_err());
        assert!(verify_mfa_token(&restore, SECRET).is_err());
    }

    #[test]
    fn a_token_without_an_audience_is_refused() {
        #[derive(Serialize)]
        struct Old {
            sub: String,
            iat: usize,
            exp: usize,
            ver: i32,
        }
        let now = Utc::now().timestamp() as usize;
        let old = encode(
            &Header::default(),
            &Old {
                sub: "u1".into(),
                iat: now,
                exp: now + 600,
                ver: 0,
            },
            &EncodingKey::from_secret(SECRET.as_bytes()),
        )
        .unwrap();
        assert!(verify_access_token(&old, SECRET).is_err());
    }
}
