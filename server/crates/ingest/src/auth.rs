use actix_web::{dev::Payload, FromRequest, HttpRequest};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use iono_core::{auth::token, entities::User, AppError};
use std::future::Future;
use std::pin::Pin;

use iono_core::web::{app_state, ApiError};

use crate::state::AppState;

pub struct ApiKeyUser(pub User);

impl FromRequest for ApiKeyUser {
    type Error = ApiError;
    type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &HttpRequest, payload: &mut Payload) -> Self::Future {
        let bearer = BearerAuth::from_request(req, payload);
        let req = req.clone();
        Box::pin(async move {
            let state = app_state::<AppState>(&req)?;
            let bearer = bearer.await.map_err(|_| ApiError(AppError::Unauthorized))?;
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
            .fetch_optional(&state.db)
            .await
            .map_err(AppError::from)?
            .ok_or(ApiError(AppError::Unauthorized))?;

            if let Err(e) =
                sqlx::query("UPDATE api_keys SET last_used_at = now() WHERE token_hash = $1")
                    .bind(&hash)
                    .execute(&state.db)
                    .await
            {
                tracing::warn!(error = %e, "failed to update api key last_used_at");
            }

            Ok(ApiKeyUser(user))
        })
    }
}
