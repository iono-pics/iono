use actix_web::{get, web, HttpResponse};
use chrono::{DateTime, Utc};
use iono_core::{entities::Paste, web::ApiResult, AppError};
use serde::Serialize;
use utoipa::ToSchema;

use crate::{auth::AuthedUser, state::AppState};

#[derive(Debug, Serialize, ToSchema)]
pub struct PasteSummary {
    id: String,
    key: String,
    title: Option<String>,
    syntax: Option<String>,
    expires_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

impl From<Paste> for PasteSummary {
    fn from(paste: Paste) -> Self {
        Self {
            id: paste.id,
            key: paste.key,
            title: paste.title,
            syntax: paste.syntax,
            expires_at: paste.expires_at,
            created_at: paste.created_at,
        }
    }
}

#[utoipa::path(
    get,
    path = "/user/pastes",
    security(("bearer_auth" = [])),
    responses((status = 200, description = "the caller's pastes", body = [PasteSummary]))
)]
#[get("/pastes")]
pub async fn list_pastes(state: web::Data<AppState>, user: AuthedUser) -> ApiResult<HttpResponse> {
    let pastes = sqlx::query_as::<_, Paste>(
        "SELECT * FROM pastes WHERE user_id = $1 ORDER BY created_at DESC",
    )
    .bind(&user.0.id)
    .fetch_all(&state.db)
    .await
    .map_err(AppError::from)?;

    Ok(HttpResponse::Ok().json(
        pastes
            .into_iter()
            .map(PasteSummary::from)
            .collect::<Vec<_>>(),
    ))
}
