use actix_web::{get, patch, web, HttpResponse};
use chrono::{DateTime, Utc};
use iono_core::{
    entities::DomainSettings,
    web::{ApiResult, MapDbError, Patch},
    AppError,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{auth::AuthedUser, state::AppState};

#[derive(Debug, Serialize, ToSchema)]
pub struct DomainSettingsResponse {
    files_domain_id: Option<String>,
    files_path_prefix: Option<String>,
    pastes_domain_id: Option<String>,
    pastes_path_prefix: Option<String>,
    short_links_domain_id: Option<String>,
    short_links_path_prefix: Option<String>,
    updated_at: DateTime<Utc>,
}

impl From<DomainSettings> for DomainSettingsResponse {
    fn from(s: DomainSettings) -> Self {
        Self {
            files_domain_id: s.files_domain_id,
            files_path_prefix: s.files_path_prefix,
            pastes_domain_id: s.pastes_domain_id,
            pastes_path_prefix: s.pastes_path_prefix,
            short_links_domain_id: s.short_links_domain_id,
            short_links_path_prefix: s.short_links_path_prefix,
            updated_at: s.updated_at,
        }
    }
}

#[utoipa::path(
    get,
    path = "/user/settings/domains",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "the caller's domain routing settings", body = DomainSettingsResponse),
        (status = 401, description = "missing or invalid token"),
    )
)]
#[get("/settings/domains")]
pub async fn get_domain_settings(
    state: web::Data<AppState>,
    user: AuthedUser,
) -> ApiResult<HttpResponse> {
    let settings =
        sqlx::query_as::<_, DomainSettings>("SELECT * FROM domain_settings WHERE user_id = $1")
            .bind(&user.0.id)
            .fetch_optional(&state.db)
            .await
            .map_err(AppError::from)?
            .ok_or_else(|| AppError::internal("user has no domain_settings row"))?;

    Ok(HttpResponse::Ok().json(DomainSettingsResponse::from(settings)))
}

#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(default)]
pub struct UpdateDomainSettingsRequest {
    #[schema(value_type = Option<String>)]
    files_domain_id: Patch<String>,
    #[schema(value_type = Option<String>)]
    files_path_prefix: Patch<String>,
    #[schema(value_type = Option<String>)]
    pastes_domain_id: Patch<String>,
    #[schema(value_type = Option<String>)]
    pastes_path_prefix: Patch<String>,
    #[schema(value_type = Option<String>)]
    short_links_domain_id: Patch<String>,
    #[schema(value_type = Option<String>)]
    short_links_path_prefix: Patch<String>,
}

fn validate_prefix(value: &str) -> Result<(), AppError> {
    if value.is_empty() || value.len() > 64 {
        return Err(AppError::BadRequest(
            "path prefix must be 1-64 characters".into(),
        ));
    }
    if !value.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err(AppError::BadRequest(
            "path prefix may only contain letters, numbers, and '-'".into(),
        ));
    }
    Ok(())
}

#[utoipa::path(
    patch,
    path = "/user/settings/domains",
    request_body = UpdateDomainSettingsRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "domain settings updated", body = DomainSettingsResponse),
        (status = 400, description = "validation failed"),
        (status = 401, description = "missing or invalid token"),
        (status = 404, description = "referenced domain does not exist or is not visible"),
    )
)]
#[patch("/settings/domains")]
pub async fn update_domain_settings(
    state: web::Data<AppState>,
    user: AuthedUser,
    body: web::Json<UpdateDomainSettingsRequest>,
) -> ApiResult<HttpResponse> {
    let body = body.into_inner();

    for prefix in [
        body.files_path_prefix.as_set(),
        body.pastes_path_prefix.as_set(),
        body.short_links_path_prefix.as_set(),
    ]
    .into_iter()
    .flatten()
    {
        validate_prefix(prefix)?;
    }

    if !body.files_domain_id.is_provided()
        && !body.files_path_prefix.is_provided()
        && !body.pastes_domain_id.is_provided()
        && !body.pastes_path_prefix.is_provided()
        && !body.short_links_domain_id.is_provided()
        && !body.short_links_path_prefix.is_provided()
    {
        return Err(AppError::BadRequest("no fields to update".into()).into());
    }

    let (files_domain_p, files_domain_v) = body.files_domain_id.split();
    let (files_prefix_p, files_prefix_v) = body.files_path_prefix.split();
    let (pastes_domain_p, pastes_domain_v) = body.pastes_domain_id.split();
    let (pastes_prefix_p, pastes_prefix_v) = body.pastes_path_prefix.split();
    let (links_domain_p, links_domain_v) = body.short_links_domain_id.split();
    let (links_prefix_p, links_prefix_v) = body.short_links_path_prefix.split();

    let updated = sqlx::query_as::<_, DomainSettings>(
        r#"
        UPDATE domain_settings SET
            files_domain_id          = CASE WHEN $1  THEN $2  ELSE files_domain_id END,
            files_path_prefix        = CASE WHEN $3  THEN $4  ELSE files_path_prefix END,
            pastes_domain_id         = CASE WHEN $5  THEN $6  ELSE pastes_domain_id END,
            pastes_path_prefix       = CASE WHEN $7  THEN $8  ELSE pastes_path_prefix END,
            short_links_domain_id    = CASE WHEN $9  THEN $10 ELSE short_links_domain_id END,
            short_links_path_prefix  = CASE WHEN $11 THEN $12 ELSE short_links_path_prefix END
        WHERE user_id = $13
        RETURNING *
        "#,
    )
    .bind(files_domain_p)
    .bind(&files_domain_v)
    .bind(files_prefix_p)
    .bind(&files_prefix_v)
    .bind(pastes_domain_p)
    .bind(&pastes_domain_v)
    .bind(pastes_prefix_p)
    .bind(&pastes_prefix_v)
    .bind(links_domain_p)
    .bind(&links_domain_v)
    .bind(links_prefix_p)
    .bind(&links_prefix_v)
    .bind(&user.0.id)
    .fetch_optional(&state.db)
    .await
    .map_err(MapDbError::new().on_foreign_key_not_found().build())?;

    let Some(settings) = updated else {
        return Err(AppError::internal("user has no domain_settings row").into());
    };

    Ok(HttpResponse::Ok().json(DomainSettingsResponse::from(settings)))
}
