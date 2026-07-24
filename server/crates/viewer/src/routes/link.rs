use actix_web::{get, http::header, web, HttpResponse};
use iono_core::{entities::ShortLink, web::ApiResult, AppError};

use crate::state::AppState;

#[get("/l/{key}")]
pub async fn follow_short_link(
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> ApiResult<HttpResponse> {
    let link = sqlx::query_as::<_, ShortLink>(
        "SELECT * FROM short_links WHERE key = $1 AND (expires_at IS NULL OR expires_at > now())",
    )
    .bind(path.into_inner())
    .fetch_optional(&state.db)
    .await
    .map_err(AppError::from)?
    .ok_or(AppError::NotFound)?;

    Ok(redirect(&link))
}

#[get("/l/{prefix}/{key}")]
pub async fn follow_short_link_with_prefix(
    state: web::Data<AppState>,
    path: web::Path<(String, String)>,
) -> ApiResult<HttpResponse> {
    let (prefix, key) = path.into_inner();
    let link = sqlx::query_as::<_, ShortLink>(
        r#"
        SELECT s.* FROM short_links s
        INNER JOIN domain_settings ds ON ds.user_id = s.user_id
        WHERE s.key = $1
        AND ds.short_links_path_prefix = $2
        AND (s.expires_at IS NULL OR s.expires_at > now())
        "#,
    )
    .bind(key)
    .bind(prefix)
    .fetch_optional(&state.db)
    .await
    .map_err(AppError::from)?
    .ok_or(AppError::NotFound)?;

    Ok(redirect(&link))
}

fn redirect(link: &ShortLink) -> HttpResponse {
    HttpResponse::Found()
        .insert_header((header::LOCATION, link.target_url.clone()))
        .insert_header((header::CACHE_CONTROL, "no-store"))
        .finish()
}
