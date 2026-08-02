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

pub type AuthedUser = iono_core::auth::AuthedUser<AppState>;

pub struct JwtUser(pub User);

impl FromRequest for JwtUser {
    type Error = ApiError;
    type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &HttpRequest, payload: &mut Payload) -> Self::Future {
        let fut = state_and_bearer::<AppState>(req, payload);
        Box::pin(async move {
            let (state, bearer) = fut.await?;
            let user = jwt::authenticate(
                &state.db,
                state.config.jwt_secret.expose_secret(),
                bearer.token(),
            )
            .await?;
            Ok(JwtUser(user))
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
