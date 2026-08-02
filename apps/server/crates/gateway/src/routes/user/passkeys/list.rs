use actix_web::{get, web, HttpResponse};
use chrono::{DateTime, Utc};
use iono_core::{entities::PasskeyCredential, web::ApiResult, AppError};
use serde::Serialize;
use utoipa::ToSchema;

use crate::{auth::JwtUser, state::AppState};

#[derive(Debug, Serialize, ToSchema)]
pub struct PasskeySummary {
    id: String,
    name: Option<String>,
    created_at: DateTime<Utc>,
    last_used_at: Option<DateTime<Utc>>,
}

impl From<PasskeyCredential> for PasskeySummary {
    fn from(p: PasskeyCredential) -> Self {
        Self {
            id: p.id,
            name: p.name,
            created_at: p.created_at,
            last_used_at: p.last_used_at,
        }
    }
}

#[utoipa::path(
    get,
    path = "/user/passkeys",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "the users registered passkeys", body = [PasskeySummary]),
        (status = 401, description = "missing or invalid token")
    )
)]
#[get("/passkeys")]
pub async fn list_passkeys(state: web::Data<AppState>, user: JwtUser) -> ApiResult<HttpResponse> {
    let passkeys = sqlx::query_as::<_, PasskeyCredential>(
        "SELECT * FROM passkeys WHERE user_id = $1 ORDER BY created_at",
    )
    .bind(&user.0.id)
    .fetch_all(&state.db)
    .await
    .map_err(AppError::from)?;

    let summaries: Vec<PasskeySummary> = passkeys.into_iter().map(Into::into).collect();

    Ok(HttpResponse::Ok().json(summaries))
}
