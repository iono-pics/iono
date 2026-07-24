use actix_web::{dev::Payload, FromRequest, HttpRequest};
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;

use crate::auth::token;
use crate::entities::User;
use crate::error::AppError;
use crate::state::HasDb;
use crate::web::{state_and_bearer, ApiError};

pub struct ApiKeyUser<S>(pub User, pub PhantomData<S>);

impl<S: HasDb + 'static> FromRequest for ApiKeyUser<S> {
    type Error = ApiError;
    type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &HttpRequest, payload: &mut Payload) -> Self::Future {
        let fut = state_and_bearer::<S>(req, payload);
        Box::pin(async move {
            let (state, bearer) = fut.await?;
            let hash = token::hash_api_token(bearer.token()); // SHA256 since its fast, argon is probably better but slower
                                                              // + theres no dict to bruteforce randomly generated tokens

            let user = sqlx::query_as::<_, User>(
                r#"
                SELECT u.* FROM users u
                INNER JOIN api_keys k ON k.user_id = u.id
                WHERE k.token_hash = $1
                "#,
            )
            .bind(&hash)
            .fetch_optional(state.db())
            .await
            .map_err(AppError::from)?
            .ok_or(ApiError(AppError::Unauthorized))?;

            if let Err(e) =
                sqlx::query("UPDATE api_keys SET last_used_at = now() WHERE token_hash = $1")
                    .bind(&hash)
                    .execute(state.db())
                    .await
            {
                tracing::warn!(error = %e, "failed to update api key last_used_at");
            }

            Ok(ApiKeyUser(user, PhantomData))
        })
    }
}
