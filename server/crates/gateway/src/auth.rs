use actix_web::{dev::Payload, FromRequest, HttpRequest};
use iono_core::{
    auth::{api_key, jwt, token},
    entities::User,
    AppError,
};
use secrecy::ExposeSecret;
use std::future::Future;
use std::pin::Pin;

use iono_core::web::{state_and_bearer, ApiError};

use crate::state::AppState;

async fn authenticate_jwt(state: &AppState, access_token: &str) -> Result<User, AppError> {
    let claims = jwt::verify_access_token(access_token, state.config.jwt_secret.expose_secret())?;

    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
        .bind(&claims.sub)
        .fetch_optional(&state.db)
        .await
        .map_err(AppError::from)?
        .ok_or(AppError::Unauthorized)?;

    if claims.ver != user.token_version {
        return Err(AppError::Unauthorized);
    }

    Ok(user)
}

pub struct JwtUser(pub User);

impl FromRequest for JwtUser {
    type Error = ApiError;
    type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &HttpRequest, payload: &mut Payload) -> Self::Future {
        let fut = state_and_bearer::<AppState>(req, payload);
        Box::pin(async move {
            let (state, bearer) = fut.await?;
            Ok(JwtUser(authenticate_jwt(&state, bearer.token()).await?))
        })
    }
}

pub struct AuthedUser(pub User);

impl FromRequest for AuthedUser {
    type Error = ApiError;
    type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &HttpRequest, payload: &mut Payload) -> Self::Future {
        let fut = state_and_bearer::<AppState>(req, payload);
        Box::pin(async move {
            let (state, bearer) = fut.await?;
            let bearer_token = bearer.token();

            let user = if bearer_token.starts_with(token::API_KEY_PREFIX) {
                api_key::authenticate(&state.db, bearer_token).await?
            } else {
                authenticate_jwt(&state, bearer_token).await?
            };

            Ok(AuthedUser(user))
        })
    }
}

pub struct ApiKeyAuth(pub String);

impl FromRequest for ApiKeyAuth {
    type Error = ApiError;
    type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &HttpRequest, payload: &mut Payload) -> Self::Future {
        let fut = state_and_bearer::<AppState>(req, payload);
        Box::pin(async move {
            let (state, bearer) = fut.await?;
            let api_key = bearer.token().to_string();

            if !api_key.starts_with(token::API_KEY_PREFIX) {
                return Err(ApiError(AppError::Unauthorized));
            }

            api_key::authenticate(&state.db, &api_key).await?;
            Ok(ApiKeyAuth(api_key))
        })
    }
}
