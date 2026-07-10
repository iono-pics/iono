use actix_web::{post, web, HttpResponse};
use iono_core::{
    auth::{jwt, password, token},
    entities::User,
    AppError,
};
use regex::Regex;
use secrecy::ExposeSecret;
use serde::Deserialize;
use std::sync::LazyLock;
use uuid::Uuid;

static EMAIL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[\w.+-]+@([\w-]+\.)+[\w-]{2,}$").unwrap());

use crate::{error::ApiResult, state::AppState};

const MIN_PASSWORD_LEN: usize = 8;
const MAX_PASSWORD_LEN: usize = 256;
const MIN_USERNAME_LEN: usize = 3;
const MAX_USERNAME_LEN: usize = 32;

#[derive(Deserialize)]
pub struct SignupRequest {
    username: String,
    email: String,
    password: String,
}

#[post("/signup")]
pub async fn signup(
    state: web::Data<AppState>,
    body: web::Json<SignupRequest>,
) -> ApiResult<HttpResponse> {
    validate_signup(&body)?;

    let plain_password = body.password.clone();
    let password_hash =
        tokio::task::spawn_blocking(move || password::hash_password(&plain_password))
            .await
            .map_err(|e| AppError::internal_from("password hashing task panicked", e))??;

    let id = Uuid::new_v4().to_string();

    let user = sqlx::query_as::<_, User>(
        "INSERT INTO users (id, username, email, password_hash) VALUES ($1, $2, $3, $4) RETURNING *",
    )
    .bind(&id)
    .bind(&body.username)
    .bind(&body.email)
    .bind(&password_hash)
    .fetch_one(&state.db)
    .await
    .map_err(|e| match &e {
        sqlx::Error::Database(db_err) if db_err.kind() == sqlx::error::ErrorKind::UniqueViolation => {
            AppError::Conflict("username or email already taken".into())
        }
        _ => AppError::from(e),
    })?;

    let api_token = token::generate_api_token();
    let api_token_hash = token::hash_api_token(&api_token);
    let api_key_id = Uuid::new_v4().to_string();

    sqlx::query(
        "INSERT INTO api_keys (id, user_id, token_hash, token_prefix, name) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(&api_key_id)
    .bind(&user.id)
    .bind(&api_token_hash)
    .bind(&api_token[..13])
    .bind("default")
    .execute(&state.db)
    .await
    .map_err(AppError::from)?;

    let access_token = jwt::issue_access_token(
        &user.id,
        user.token_version,
        state.config.jwt_secret.expose_secret(),
        state.config.jwt_access_ttl_minutes,
    )?;

    Ok(HttpResponse::Created().json(serde_json::json!({
        "access_token": access_token,
    })))
}

fn validate_signup(body: &SignupRequest) -> Result<(), AppError> {
    let username_len = body.username.chars().count();
    if !(MIN_USERNAME_LEN..=MAX_USERNAME_LEN).contains(&username_len) {
        return Err(AppError::BadRequest(format!(
            "username must be {MIN_USERNAME_LEN}-{MAX_USERNAME_LEN} characters"
        )));
    }
    if !body
        .username
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(AppError::BadRequest(
            "username may only contain letters, numbers, '_', and '-'".into(),
        ));
    }

    if !is_email(&body.email) {
        return Err(AppError::BadRequest("invalid email address".into()));
    }

    let password_len = body.password.chars().count();
    if password_len < MIN_PASSWORD_LEN {
        return Err(AppError::BadRequest(format!(
            "password must be at least {MIN_PASSWORD_LEN} characters"
        )));
    }
    if password_len > MAX_PASSWORD_LEN {
        return Err(AppError::BadRequest(format!(
            "password must be at most {MAX_PASSWORD_LEN} characters"
        )));
    }

    Ok(())
}

fn is_email(email: &str) -> bool {
    EMAIL_RE.is_match(email)
}
