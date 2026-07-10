use actix_web::{dev::Payload, web, FromRequest, HttpRequest};
use iono_core::{auth::token, entities::User, AppError};
use std::future::Future;
use std::pin::Pin;

use crate::{error::ApiError, state::AppState};

pub struct ApiKeyUser(pub User);

impl FromRequest for ApiKeyUser {
    type Error = ApiError;
    type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let req = req.clone();
        Box::pin(async move {
            let state = app_state(&req)?;
            let raw = bearer_token(&req).ok_or(ApiError(AppError::Unauthorized))?;
            let hash = token::hash_api_token(&raw); // SHA256 since its fast, argon is probably better but slower
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

fn app_state(req: &HttpRequest) -> Result<web::Data<AppState>, ApiError> {
    req.app_data::<web::Data<AppState>>()
        .cloned()
        .ok_or_else(|| ApiError(AppError::internal("AppState not registered")))
}

fn bearer_token(req: &HttpRequest) -> Option<String> {
    let raw = req.headers().get("Authorization")?.to_str().ok()?;
    Some(raw.strip_prefix("Bearer ").unwrap_or(raw).to_string())
}
