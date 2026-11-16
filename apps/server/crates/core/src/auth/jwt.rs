use chrono::{DateTime, Duration, Utc};
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

const MFA_TOKEN_PURPOSE: &str = "mfa_pending";
const MFA_TOKEN_TTL_MINUTES: i64 = 5;

const RESTORE_TOKEN_PURPOSE: &str = "restore_account";
const RESTORE_TOKEN_TTL_MINUTES: i64 = 15;

fn validation_for(audience: &str) -> Validation {
    let mut validation = Validation::default();
    validation.set_audience(&[audience]);
    validation.set_required_spec_claims(&["exp", "sub", "aud"]);
    validation
}

/// claims of an access token
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub aud: String,
    pub iat: usize,
    pub exp: usize,
    pub ver: i32,
}

/// claims of a short lived token that only authorises one step, such as
/// finishing a login with a second factor or restoring a deleted account
#[derive(Debug, Serialize, Deserialize)]
pub struct PurposeClaims {
    pub sub: String,
    pub aud: String,
    pub iat: usize,
    pub exp: usize,
    pub purpose: String,
}

fn unix_seconds(time: DateTime<Utc>) -> Result<usize, AppError> {
    usize::try_from(time.timestamp())
        .map_err(|e| AppError::internal_from("token time is out of range", e))
}

/// the issue and expiry times for a token that lives `ttl_minutes`
fn lifetime(ttl_minutes: i64) -> Result<(usize, usize), AppError> {
    let now = Utc::now();
    let expires = Duration::try_minutes(ttl_minutes)
        .and_then(|ttl| now.checked_add_signed(ttl))
        .ok_or_else(|| AppError::internal("token ttl is out of range"))?;
    Ok((unix_seconds(now)?, unix_seconds(expires)?))
}

fn sign<T: Serialize>(claims: &T, secret: &str) -> Result<String, AppError> {
    encode(
        &Header::default(),
        claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| AppError::internal_from("jwt encode failed", e))
}

fn issue_purpose_token(
    user_id: &str,
    secret: &str,
    audience: &str,
    purpose: &str,
    ttl_minutes: i64,
) -> Result<String, AppError> {
    let (iat, exp) = lifetime(ttl_minutes)?;
    sign(
        &PurposeClaims {
            sub: user_id.to_string(),
            aud: audience.to_string(),
            iat,
            exp,
            purpose: purpose.to_string(),
        },
        secret,
    )
}

fn verify_purpose_token(
    token: &str,
    secret: &str,
    audience: &str,
    purpose: &str,
) -> Result<PurposeClaims, AppError> {
    let claims = decode::<PurposeClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation_for(audience),
    )
    .map(|data| data.claims)
    .map_err(|_| AppError::Unauthorized)?;

    if claims.purpose != purpose {
        return Err(AppError::Unauthorized);
    }

    Ok(claims)
}

/// signs an access token for `user_id` that lives `ttl_minutes`
///
/// # Errors
///
/// Returns an internal error when the ttl is out of range or signing fails.
pub fn issue_access_token(
    user_id: &str,
    token_version: i32,
    secret: &str,
    ttl_minutes: i64,
) -> Result<String, AppError> {
    let (iat, exp) = lifetime(ttl_minutes)?;
    sign(
        &Claims {
            sub: user_id.to_string(),
            aud: ACCESS_AUDIENCE.to_string(),
            iat,
            exp,
            ver: token_version,
        },
        secret,
    )
}

/// checks the signature, expiry and audience of an access token
///
/// # Errors
///
/// Returns [`AppError::Unauthorized`] for any token that does not verify.
pub fn verify_access_token(token: &str, secret: &str) -> Result<Claims, AppError> {
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation_for(ACCESS_AUDIENCE),
    )
    .map(|data| data.claims)
    .map_err(|_| AppError::Unauthorized)
}

/// resolves an access token to its user, refusing revoked tokens and
/// deleted accounts
///
/// # Errors
///
/// Returns [`AppError::Unauthorized`] when the token does not verify, the user
/// is gone or deleted, or the token version was revoked, and a database error
/// when the lookup fails.
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

/// signs the token that proves the password step of a login passed and a
/// second factor is still owed
///
/// # Errors
///
/// Returns an internal error when signing fails.
pub fn issue_mfa_token(user_id: &str, secret: &str) -> Result<String, AppError> {
    issue_purpose_token(
        user_id,
        secret,
        MFA_AUDIENCE,
        MFA_TOKEN_PURPOSE,
        MFA_TOKEN_TTL_MINUTES,
    )
}

/// checks a token from [`issue_mfa_token`]
///
/// # Errors
///
/// Returns [`AppError::Unauthorized`] for any token that does not verify.
pub fn verify_mfa_token(token: &str, secret: &str) -> Result<PurposeClaims, AppError> {
    verify_purpose_token(token, secret, MFA_AUDIENCE, MFA_TOKEN_PURPOSE)
}

/// signs the token that lets a user restore a deleted account
///
/// # Errors
///
/// Returns an internal error when signing fails.
pub fn issue_restore_token(user_id: &str, secret: &str) -> Result<String, AppError> {
    issue_purpose_token(
        user_id,
        secret,
        RESTORE_AUDIENCE,
        RESTORE_TOKEN_PURPOSE,
        RESTORE_TOKEN_TTL_MINUTES,
    )
}

/// checks a token from [`issue_restore_token`]
///
/// # Errors
///
/// Returns [`AppError::Unauthorized`] for any token that does not verify.
pub fn verify_restore_token(token: &str, secret: &str) -> Result<PurposeClaims, AppError> {
    verify_purpose_token(token, secret, RESTORE_AUDIENCE, RESTORE_TOKEN_PURPOSE)
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
    fn an_out_of_range_ttl_is_an_error_not_a_panic() {
        assert!(issue_access_token("u1", 0, SECRET, i64::MAX).is_err());
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
        let now = unix_seconds(Utc::now()).unwrap();
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
