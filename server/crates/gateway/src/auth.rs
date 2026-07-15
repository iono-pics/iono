use actix_web::{dev::Payload, FromRequest, HttpRequest};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use iono_core::{auth::jwt, entities::User, AppError};
use secrecy::ExposeSecret;
use std::future::Future;
use std::pin::Pin;

use iono_core::web::{app_state, ApiError};

use crate::state::AppState;

pub struct JwtUser(pub User);

impl FromRequest for JwtUser {
    type Error = ApiError;
    type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &HttpRequest, payload: &mut Payload) -> Self::Future {
        let bearer = BearerAuth::from_request(req, payload);
        let req = req.clone();
        Box::pin(async move {
            let state = app_state::<AppState>(&req)?;
            let bearer = bearer.await.map_err(|_| ApiError(AppError::Unauthorized))?;
            let claims =
                jwt::verify_access_token(bearer.token(), state.config.jwt_secret.expose_secret())?;

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
