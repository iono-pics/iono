use actix_web::{post, web, HttpResponse};
use email_address::EmailAddress;
use iono_core::{
    auth::{jwt, password, token},
    entities::User,
    AppError,
};
use secrecy::ExposeSecret;
use serde::Deserialize;
use utoipa::ToSchema;
use uuid::Uuid;
use validator::{Validate, ValidationError};

use iono_core::web::ApiResult;

use crate::state::AppState;

#[derive(Deserialize, Validate, ToSchema)]
pub struct SignupRequest {
    #[validate(
        length(min = 3, max = 32, message = "username must be 3-32 characters"),
        custom(
            function = "username_chars",
            message = "username may only contain letters, numbers, '_', and '-'"
        )
    )]
    username: String,
    #[validate(custom(function = "email", message = "invalid email address"))]
    email: String,
    #[validate(length(min = 8, max = 256, message = "password must be 8-256 characters"))]
    password: String,
}

fn username_chars(username: &str) -> Result<(), ValidationError> {
    if username
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        Ok(())
    } else {
        Err(ValidationError::new("username_chars"))
    }
}

fn email(email: &str) -> Result<(), ValidationError> {
    if EmailAddress::is_valid(email) {
        Ok(())
    } else {
        Err(ValidationError::new("email"))
    }
}

#[utoipa::path(
    post,
    path = "/auth/signup",
    request_body = SignupRequest,
    responses(
        (status = 201, description = "account created"),
        (status = 400, description = "validation failed"),
        (status = 409, description = "username or email already taken")
    )
)]
#[post("/signup")]
pub async fn signup(
    state: web::Data<AppState>,
    body: web::Json<SignupRequest>,
) -> ApiResult<HttpResponse> {
    body.validate()
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

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
