use actix_web::{post, web, HttpResponse};
use iono_core::{
    auth::{jwt, password::verify_password_async},
    entities::User,
    AppError,
};
use secrecy::ExposeSecret;
use serde::Deserialize;
use utoipa::ToSchema;

use iono_core::web::ApiResult;

use crate::state::AppState;

#[derive(Deserialize, ToSchema)]
pub struct LoginRequest {
    /// username or email
    identifier: String,
    password: String,
}

#[utoipa::path(
    post,
    path = "/auth/login",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "returns access token"),
        (status = 401, description = "invalid credentials")
    )
)]
#[post("/login")]
pub async fn login(
    state: web::Data<AppState>,
    body: web::Json<LoginRequest>,
) -> ApiResult<HttpResponse> {
    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE email = $1 OR username = $1")
        .bind(&body.identifier)
        .fetch_optional(&state.db)
        .await
        .map_err(AppError::from)?
        .ok_or(AppError::Unauthorized)?;

    let Some(password_hash) = user.password_hash.clone() else {
        return Err(AppError::Unauthorized.into());
    };

    let verified = verify_password_async(body.password.clone(), password_hash).await?;

    if !verified {
        return Err(AppError::Unauthorized.into());
    }

    let access_token = jwt::issue_access_token(
        &user.id,
        user.token_version,
        state.config.jwt_secret.expose_secret(),
        state.config.jwt_access_ttl_minutes,
    )?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "access_token": access_token,
    })))
}
