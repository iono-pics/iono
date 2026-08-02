use actix_web::{post, web, HttpResponse};
use chrono::{Duration, Utc};
use iono_core::{auth::token, entities::UserSettings, web::ApiResult, AppError};
use serde::Deserialize;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{auth::AuthedUser, state::AppState};

const MAX_TARGET_URL_LENGTH: usize = 2048; // nax len allowed in search bar

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateShortLinkRequest {
    target_url: String,
}

#[utoipa::path(
    post,
    path = "/links",
    request_body = CreateShortLinkRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 201, description = "short link created"),
        (status = 400, description = "invalid target url"),
        (status = 401, description = "missing or invalid token")
    )
)]
#[post("/links")]
pub async fn create_short_link(
    state: web::Data<AppState>,
    user: AuthedUser,
    body: web::Json<CreateShortLinkRequest>,
) -> ApiResult<HttpResponse> {
    let target_url = body.into_inner().target_url.trim().to_string();
    validate(&target_url)?;

    let settings =
        sqlx::query_as::<_, UserSettings>("SELECT * FROM user_settings WHERE user_id = $1")
            .bind(&user.0.id)
            .fetch_optional(&state.db)
            .await
            .map_err(AppError::from)?
            .ok_or_else(|| AppError::internal("user has no settings configured"))?;

    let expires_at = settings
        .default_expires_in_seconds
        .map(|seconds| Utc::now() + Duration::seconds(seconds));

    let mut link = None;
    for _ in 0..5 {
        let id = Uuid::new_v4().to_string();
        let key = token::generate_display_name(
            settings.display_name_length as usize,
            &settings.display_name_style,
        );
        link = sqlx::query_as::<_, (String, String)>(
            r#"
            INSERT INTO short_links (id, user_id, key, target_url, expires_at)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (key) DO NOTHING
            RETURNING id, key
            "#,
        )
        .bind(id)
        .bind(&user.0.id)
        .bind(key)
        .bind(&target_url)
        .bind(expires_at)
        .fetch_optional(&state.db)
        .await
        .map_err(AppError::from)?;

        if link.is_some() {
            break;
        }
    }

    let (id, key) =
        link.ok_or_else(|| AppError::internal("failed to generate a unique short link key"))?;

    let (domain, path_prefix) = sqlx::query_as::<_, (String, Option<String>)>(
        r#"
        SELECT d.name, ds.short_links_path_prefix
        FROM domain_settings ds
        INNER JOIN domains d ON d.id = ds.short_links_domain_id
        WHERE ds.user_id = $1
        "#,
    )
    .bind(&user.0.id)
    .fetch_optional(&state.db)
    .await
    .map_err(AppError::from)?
    .ok_or_else(|| AppError::internal("user has no short links domain configured"))?;

    let prefix = path_prefix
        .map(|prefix| format!("{prefix}/"))
        .unwrap_or_default();

    Ok(HttpResponse::Created().json(serde_json::json!({
        "id": id,
        "key": key,
        "url": format!("https://{domain}/l/{prefix}{key}"),
        "expires_at": expires_at,
    })))
}

fn validate(target_url: &str) -> Result<(), AppError> {
    if target_url.len() > MAX_TARGET_URL_LENGTH {
        return Err(AppError::BadRequest(
            "target url must be at most 2048 characters".into(),
        ));
    }
    if !target_url.starts_with("http://") && !target_url.starts_with("https://") {
        return Err(AppError::BadRequest(
            "target url must start with http:// or https://".into(),
        ));
    }
    Ok(())
}
