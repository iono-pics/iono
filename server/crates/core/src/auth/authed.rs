use actix_web::{dev::Payload, FromRequest, HttpRequest};
use secrecy::ExposeSecret;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;

use crate::auth::{api_key, jwt, token};
use crate::entities::User;
use crate::state::{HasDb, HasJwtSecret};
use crate::web::{state_and_bearer, ApiError};

pub struct AuthedUser<S>(pub User, pub PhantomData<S>);

impl<S: HasDb + HasJwtSecret + 'static> FromRequest for AuthedUser<S> {
    type Error = ApiError;
    type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &HttpRequest, payload: &mut Payload) -> Self::Future {
        let fut = state_and_bearer::<S>(req, payload);
        Box::pin(async move {
            let (state, bearer) = fut.await?;
            let bearer_token = bearer.token();

            let user = if bearer_token.starts_with(token::API_KEY_PREFIX) {
                api_key::authenticate(state.db(), bearer_token).await?
            } else {
                jwt::authenticate(state.db(), state.jwt_secret().expose_secret(), bearer_token)
                    .await?
            };

            Ok(AuthedUser(user, PhantomData))
        })
    }
}
