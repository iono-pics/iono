use actix_web::{get, web, HttpResponse};
use chrono::{DateTime, Utc};
use iono_core::{entities::ShortLink, web::ApiResult, AppError};
use serde::Serialize;
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

#[utoipa::path(
    get,
    path = "/user/links",
    security(("bearer_auth" = [])),
    responses((status = 200, description = "the callers short links", body = [ShortLinkSummary]))
)]
#[get("/links")]
pub async fn list_short_links(
    state: web::Data<AppState>,
    user: AuthedUser,
) -> ApiResult<HttpResponse> {
    let links = sqlx::query_as::<_, ShortLink>(
        "SELECT * FROM short_links WHERE user_id = $1 ORDER BY created_at DESC",
    )
    .bind(&user.0.id)
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
