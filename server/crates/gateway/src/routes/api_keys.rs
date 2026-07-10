use actix_web::{post, web, HttpResponse};
use iono_core::{auth::token, AppError};
use uuid::Uuid;

use crate::{auth::JwtUser, error::ApiResult, state::AppState};

#[post("/apikeys/regenerate")]
pub async fn regenerate_apikey(
    state: web::Data<AppState>,
    user: JwtUser,
) -> ApiResult<HttpResponse> {
    let api_token = token::generate_api_token();
    let token_hash = token::hash_api_token(&api_token);
    let id = Uuid::new_v4().to_string();

    sqlx::query(
        r#"
        INSERT INTO api_keys (id, user_id, token_hash, token_prefix, name)
        VALUES ($1, $2, $3, $4, 'default')
        ON CONFLICT (user_id) DO UPDATE
        SET token_hash = EXCLUDED.token_hash,
            token_prefix = EXCLUDED.token_prefix,
            last_used_at = NULL
        "#,
    )
    .bind(&id)
    .bind(&user.0.id)
    .bind(&token_hash)
    .bind(&api_token[..13])
    .execute(&state.db)
    .await
    .map_err(AppError::from)?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "api_key": api_token,
    })))
}
