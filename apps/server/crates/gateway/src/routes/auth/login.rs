use actix_web::{post, web, HttpRequest, HttpResponse};
use iono_core::{
    auth::{password::verify_password_async, refresh::SessionContext},
    entities::User,
    AppError,
};
use secrecy::ExposeSecret;
use serde::Deserialize;
use utoipa::ToSchema;

use iono_core::web::ApiResult;

use crate::{
    routes::auth::{mfa_challenge, signed_in_payload},
    state::AppState,
};

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
        (status = 200, description = "returns access token and refresh token, or {mfa_required: true, mfa_token} if mfa is enabled"),
        (status = 401, description = "invalid credentials"),
        (status = 409, description = "the account requires a passkey but has none registered")
    )
)]
#[post("/login")]
pub async fn login(
    req: HttpRequest,
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

    if let Some(challenge) =
        mfa_challenge(&state.db, state.config.jwt_secret.expose_secret(), &user).await?
    {
        return Ok(HttpResponse::Ok().json(challenge.json()));
    }

    let payload = signed_in_payload(
        &state,
        &user.id,
        user.token_version,
        &SessionContext::from_request(&req),
    )
    .await?;

    Ok(HttpResponse::Ok().json(payload))
}
