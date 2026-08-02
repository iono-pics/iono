use actix_web::{patch, web, HttpResponse};
use chrono::{DateTime, Utc};
use iono_core::{entities::ShortLink, web::ApiResult, AppError};
use serde::{Deserialize, Deserializer};
use utoipa::ToSchema;

use crate::{auth::AuthedUser, routes::user::links::list::ShortLinkSummary, state::AppState};

const MAX_TARGET_URL_LENGTH: usize = 2048;

#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct UpdateShortLinkRequest {
    target_url: Option<String>,
    #[serde(default, deserialize_with = "deserialize_some")]
    expires_at: Option<Option<DateTime<Utc>>>,
}

fn deserialize_some<'de, T, D>(deserializer: D) -> Result<Option<T>, D::Error>
where
    T: Deserialize<'de>,
    D: Deserializer<'de>,
{
    T::deserialize(deserializer).map(Some)
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
    validate(
        target_url.as_deref(),
        body.expires_at.as_ref().and_then(|v| v.as_ref()),
    )?;

    if target_url.is_none() && body.expires_at.is_none() {
        return Err(AppError::BadRequest("no fields to update".into()).into());
    }

    let expires_provided = body.expires_at.is_some();
    let expires_value = body.expires_at.flatten();

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

    let Some(link) = updated else {
        return Err(AppError::NotFound.into());
    };

    Ok(HttpResponse::Ok().json(ShortLinkSummary::from(link)))
}

fn validate(target_url: Option<&str>, expires_at: Option<&DateTime<Utc>>) -> Result<(), AppError> {
    if let Some(url) = target_url {
        if url.len() > MAX_TARGET_URL_LENGTH {
            return Err(AppError::BadRequest(format!(
                "target_url must be at most {MAX_TARGET_URL_LENGTH} characters"
            )));
        }
        if !url.starts_with("http://") && !url.starts_with("https://") {
            return Err(AppError::BadRequest(
                "target_url must start with http:// or https://".into(),
            ));
        }
    }

    if let Some(at) = expires_at {
        if *at <= Utc::now() {
            return Err(AppError::BadRequest(
                "expires_at must be in the future".into(),
            ));
        }
    }

    Ok(())
}
