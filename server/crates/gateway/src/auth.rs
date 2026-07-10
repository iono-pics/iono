use actix_web::{dev::Payload, web, FromRequest, HttpRequest};
use iono_core::{auth::jwt, entities::User, AppError};
use secrecy::ExposeSecret;
use std::future::Future;
use std::pin::Pin;

use crate::{error::ApiError, state::AppState};

pub struct JwtUser(pub User);

impl FromRequest for JwtUser {
    type Error = ApiError;
    type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let req = req.clone();
        Box::pin(async move {
            let state = app_state(&req)?;
            let bearer = bearer_token(&req).ok_or(ApiError(AppError::Unauthorized))?;
            let claims =
                jwt::verify_access_token(&bearer, state.config.jwt_secret.expose_secret())?;

            let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
                .bind(&claims.sub)
                .fetch_optional(&state.db)
                .await
                .map_err(AppError::from)?
                .ok_or(ApiError(AppError::Unauthorized))?;

            if claims.ver != user.token_version {
                return Err(ApiError(AppError::Unauthorized));
            }

            Ok(JwtUser(user))
        })
    }
}

fn app_state(req: &HttpRequest) -> Result<web::Data<AppState>, ApiError> {
    req.app_data::<web::Data<AppState>>()
        .cloned()
        .ok_or_else(|| ApiError(AppError::internal("AppState not registered")))
}

fn bearer_token(req: &HttpRequest) -> Option<String> {
    let raw = req.headers().get("Authorization")?.to_str().ok()?;
    Some(raw.strip_prefix("Bearer ").unwrap_or(raw).to_string())
}
