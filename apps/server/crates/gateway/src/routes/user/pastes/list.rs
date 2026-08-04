use actix_web::{get, web, HttpResponse};
use chrono::{DateTime, Utc};
use iono_core::{
    entities::Paste,
    web::{ApiResult, Page},
    AppError,
};
use serde::{Deserialize, Serialize};
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

#[derive(Debug, Deserialize)]
pub struct ListPastesQuery {
    limit: Option<i64>,
    offset: Option<i64>,
}

#[utoipa::path(
    get,
    path = "/user/pastes",
    security(("bearer_auth" = [])),
    params(
        ("limit" = Option<i64>, Query, description = "page size, 1-200 (default 50)"),
        ("offset" = Option<i64>, Query, description = "offset for pagination, default 0"),
    ),
    responses(
        (status = 200, description = "the caller's pastes", body = [PasteSummary]),
        (status = 400, description = "invalid query parameters"),
        (status = 401, description = "missing or invalid token"),
    )
)]
#[get("/pastes")]
pub async fn list_pastes(
    state: web::Data<AppState>,
    user: AuthedUser,
    query: web::Query<ListPastesQuery>,
) -> ApiResult<HttpResponse> {
    let (limit, offset) = Page {
        limit: query.limit,
        offset: query.offset,
    }
    .resolve(50, 200);

    let pastes = sqlx::query_as::<_, Paste>(
        "SELECT * FROM pastes WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
    )
    .bind(&user.0.id)
    .bind(limit)
    .bind(offset)
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
