use actix_web::{patch, web, HttpResponse};
use chrono::{DateTime, Utc};
use iono_core::{
    entities::ShortLink,
    validators,
    web::{ApiResult, OptionExt, Patch},
    AppError,
};
use serde::Deserialize;
use utoipa::ToSchema;

use crate::{auth::AuthedUser, routes::user::links::list::ShortLinkSummary, state::AppState};

#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(default)]
pub struct UpdateShortLinkRequest {
    target_url: Option<String>,
    #[schema(value_type = Option<DateTime<Utc>>)]
    expires_at: Patch<DateTime<Utc>>,
}

#[utoipa::path(
    patch,
    path = "/user/links/{id}",
    request_body = UpdateShortLinkRequest,
    security(("bearer_auth" = [])),
    params(("id" = String, Path, description = "short link id")),
    responses(
        (status = 200, description = "short link updated", body = ShortLinkSummary),
        (status = 400, description = "validation failed"),
        (status = 401, description = "missing or invalid token"),
        (status = 404, description = "no such short link"),
    )
)]
#[patch("/links/{id}")]
pub async fn update_short_link(
    state: web::Data<AppState>,
    user: AuthedUser,
    path: web::Path<String>,
    body: web::Json<UpdateShortLinkRequest>,
) -> ApiResult<HttpResponse> {
    let body = body.into_inner();
    let target_url = body.target_url.map(|u| u.trim().to_string());
    validate(target_url.as_deref(), body.expires_at.as_set())?;

    if target_url.is_none() && !body.expires_at.is_provided() {
        return Err(AppError::BadRequest("no fields to update".into()).into());
    }

    let (expires_provided, expires_value) = body.expires_at.split();
    let link_id = path.into_inner();

    let updated = sqlx::query_as::<_, ShortLink>(
        r#"
        UPDATE short_links SET
            target_url = COALESCE($1, target_url),
            expires_at = CASE WHEN $2 THEN $3 ELSE expires_at END
        WHERE id = $4 AND user_id = $5
        RETURNING *
        "#,
    )
    .bind(&target_url)
    .bind(expires_provided)
    .bind(expires_value)
    .bind(&link_id)
    .bind(&user.0.id)
    .fetch_optional(&state.db)
    .await
    .map_err(AppError::from)?;

    let link = updated.ok_or_not_found()?;

    Ok(HttpResponse::Ok().json(ShortLinkSummary::from(link)))
}

fn validate(target_url: Option<&str>, expires_at: Option<&DateTime<Utc>>) -> Result<(), AppError> {
    if let Some(url) = target_url {
        validators::http_url(url, 2048)?;
    }

    if let Some(at) = expires_at {
        validators::future_datetime(*at)?;
    }

    Ok(())
}
