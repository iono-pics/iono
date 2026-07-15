use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

use crate::error::AppError;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
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
        &Validation::default(),
    )
    .map(|data| data.claims)
    .map_err(|_| AppError::Unauthorized)
}

const MFA_TOKEN_PURPOSE: &str = "mfa_pending";

#[derive(Debug, Serialize, Deserialize)]
pub struct MfaClaims {
    pub sub: String,
    pub iat: usize,
    pub exp: usize,
    pub purpose: String,
}

pub fn issue_mfa_token(user_id: &str, secret: &str) -> Result<String, AppError> {
    let now = Utc::now();
    let claims = MfaClaims {
        sub: user_id.to_string(),
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
        &Validation::default(),
    )
    .map(|data| data.claims)
    .map_err(|_| AppError::Unauthorized)?;

    if claims.purpose != MFA_TOKEN_PURPOSE {
        return Err(AppError::Unauthorized);
    }

    Ok(claims)
}
