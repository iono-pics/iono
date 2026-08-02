use actix_web::{get, patch, web, HttpResponse};
use chrono::{DateTime, Utc};
use iono_core::{
    entities::EmbedSettings,
    web::{ApiResult, MapDbError, Patch},
    AppError,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{auth::AuthedUser, state::AppState};

#[derive(Debug, Serialize, ToSchema)]
pub struct EmbedSettingsResponse {
    enabled: bool,
    active_preset_id: Option<String>,
    updated_at: DateTime<Utc>,
}

impl From<EmbedSettings> for EmbedSettingsResponse {
    fn from(s: EmbedSettings) -> Self {
        Self {
            enabled: s.enabled,
            active_preset_id: s.active_preset_id,
            updated_at: s.updated_at,
        }
    }
}

#[utoipa::path(
    get,
    path = "/user/embeds/settings",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "the caller's embed settings", body = EmbedSettingsResponse),
        (status = 401, description = "missing or invalid token"),
    )
)]
#[get("/embeds/settings")]
pub async fn get_embed_settings(
    state: web::Data<AppState>,
    user: AuthedUser,
) -> ApiResult<HttpResponse> {
    let settings =
        sqlx::query_as::<_, EmbedSettings>("SELECT * FROM embed_settings WHERE user_id = $1")
            .bind(&user.0.id)
            .fetch_optional(&state.db)
            .await
            .map_err(AppError::from)?
            .ok_or_else(|| AppError::internal("user has no embed_settings row"))?;

    Ok(HttpResponse::Ok().json(EmbedSettingsResponse::from(settings)))
}

#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(default)]
pub struct UpdateEmbedSettingsRequest {
    enabled: Option<bool>,
    #[schema(value_type = Option<String>)]
    active_preset_id: Patch<String>,
}

#[utoipa::path(
    patch,
    path = "/user/embeds/settings",
    request_body = UpdateEmbedSettingsRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "embed settings updated", body = EmbedSettingsResponse),
        (status = 400, description = "validation failed"),
        (status = 401, description = "missing or invalid token"),
        (status = 404, description = "referenced preset does not exist"),
        (status = 409, description = "cannot enable embeds without selecting an active preset"),
    )
)]
#[patch("/embeds/settings")]
pub async fn update_embed_settings(
    state: web::Data<AppState>,
    user: AuthedUser,
    body: web::Json<UpdateEmbedSettingsRequest>,
) -> ApiResult<HttpResponse> {
    let body = body.into_inner();

    if body.enabled.is_none() && !body.active_preset_id.is_provided() {
        return Err(AppError::BadRequest("no fields to update".into()).into());
    }

    let (preset_provided, preset_value) = body.active_preset_id.split();

    let updated = sqlx::query_as::<_, EmbedSettings>(
        r#"
        UPDATE embed_settings SET
            enabled          = COALESCE($1, enabled),
            active_preset_id = CASE WHEN $2 THEN $3 ELSE active_preset_id END
        WHERE user_id = $4
        RETURNING *
        "#,
    )
    .bind(body.enabled)
    .bind(preset_provided)
    .bind(&preset_value)
    .bind(&user.0.id)
    .fetch_optional(&state.db)
    .await
    .map_err(
        MapDbError::new()
            .on_foreign_key_not_found()
            .on_check_conflict("cannot enable embeds without selecting an active preset")
            .build(),
    )?;

    let Some(settings) = updated else {
        return Err(AppError::internal("user has no embed_settings row").into());
    };

    Ok(HttpResponse::Ok().json(EmbedSettingsResponse::from(settings)))
}
