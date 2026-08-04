use actix_web::{get, web, HttpResponse};
use chrono::{DateTime, Utc};
use iono_core::{
    entities::ShortLink,
    web::{ApiResult, Page},
    AppError,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{auth::AuthedUser, state::AppState};

#[derive(Debug, Serialize, ToSchema)]
pub struct ShortLinkSummary {
    id: String,
    key: String,
    target_url: String,
    expires_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

impl From<ShortLink> for ShortLinkSummary {
    fn from(link: ShortLink) -> Self {
        Self {
            id: link.id,
            key: link.key,
            target_url: link.target_url,
            expires_at: link.expires_at,
            created_at: link.created_at,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ListShortLinksQuery {
    limit: Option<i64>,
    offset: Option<i64>,
}

#[utoipa::path(
    get,
    path = "/user/links",
    security(("bearer_auth" = [])),
    params(
        ("limit" = Option<i64>, Query, description = "page size, 1-200 (default 50)"),
        ("offset" = Option<i64>, Query, description = "offset for pagination, default 0"),
    ),
    responses(
        (status = 200, description = "the callers short links", body = [ShortLinkSummary]),
        (status = 400, description = "invalid query parameters"),
        (status = 401, description = "missing or invalid token"),
    )
)]
#[get("/links")]
pub async fn list_short_links(
    state: web::Data<AppState>,
    user: AuthedUser,
    query: web::Query<ListShortLinksQuery>,
) -> ApiResult<HttpResponse> {
    let (limit, offset) = Page {
        limit: query.limit,
        offset: query.offset,
    }
    .resolve(50, 200);

    let links = sqlx::query_as::<_, ShortLink>(
        "SELECT * FROM short_links WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
    )
    .bind(&user.0.id)
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.db)
    .await
    .map_err(AppError::from)?;

    Ok(HttpResponse::Ok().json(
        links
            .into_iter()
            .map(ShortLinkSummary::from)
            .collect::<Vec<_>>(),
    ))
}
