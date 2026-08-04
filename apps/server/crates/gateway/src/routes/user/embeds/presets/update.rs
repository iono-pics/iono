use actix_web::{patch, web, HttpResponse};
use iono_core::{
    entities::EmbedPreset,
    web::{ApiResult, MapDbError, OptionExt, Patch},
    AppError,
};
use serde::Deserialize;
use utoipa::ToSchema;
use validator::Validate;

use crate::{
    auth::AuthedUser,
    routes::user::embeds::presets::{EmbedPresetResponse, PresetFields},
    state::AppState,
};

#[derive(Debug, Default, Deserialize, Validate, ToSchema)]
#[serde(default)]
pub struct UpdateEmbedPresetRequest {
    #[validate(length(min = 1, max = 64, message = "must be 1-64 characters"))]
    name: Option<String>,
    #[schema(value_type = Option<String>)]
    site_name: Patch<String>,
    #[schema(value_type = Option<String>)]
    site_url: Patch<String>,
    #[schema(value_type = Option<String>)]
    author_name: Patch<String>,
    #[schema(value_type = Option<String>)]
    author_url: Patch<String>,
    #[schema(value_type = Option<String>)]
    title: Patch<String>,
    #[schema(value_type = Option<String>)]
    description: Patch<String>,
    #[schema(value_type = Option<String>)]
    color: Patch<String>,
}

impl UpdateEmbedPresetRequest {
    fn has_updates(&self) -> bool {
        self.name.is_some()
            || [
                &self.site_name,
                &self.site_url,
                &self.author_name,
                &self.author_url,
                &self.title,
                &self.description,
                &self.color,
            ]
            .iter()
            .any(|patch| patch.is_provided())
    }
}

#[utoipa::path(
    patch,
    path = "/user/embeds/presets/{id}",
    request_body = UpdateEmbedPresetRequest,
    security(("bearer_auth" = [])),
    params(("id" = String, Path, description = "preset id")),
    responses(
        (status = 200, description = "preset updated", body = EmbedPresetResponse),
        (status = 400, description = "validation failed"),
        (status = 401, description = "missing or invalid token"),
        (status = 404, description = "no such preset"),
        (status = 409, description = "a preset with that name already exists"),
    )
)]
#[patch("/embeds/presets/{id}")]
pub async fn update_embed_preset(
    state: web::Data<AppState>,
    user: AuthedUser,
    path: web::Path<String>,
    body: web::Json<UpdateEmbedPresetRequest>,
) -> ApiResult<HttpResponse> {
    body.validate()
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    let body = body.into_inner();

    PresetFields {
        site_name: body.site_name.as_deref(),
        site_url: body.site_url.as_deref(),
        author_name: body.author_name.as_deref(),
        author_url: body.author_url.as_deref(),
        title: body.title.as_deref(),
        description: body.description.as_deref(),
        color: body.color.as_deref(),
    }
    .validate()?;

    if !body.has_updates() {
        return Err(AppError::BadRequest("no fields to update".into()).into());
    }

    let (site_name_p, site_name_v) = body.site_name.split();
    let (site_url_p, site_url_v) = body.site_url.split();
    let (author_name_p, author_name_v) = body.author_name.split();
    let (author_url_p, author_url_v) = body.author_url.split();
    let (title_p, title_v) = body.title.split();
    let (description_p, description_v) = body.description.split();
    let (color_p, color_v) = body.color.split();

    let preset_id = path.into_inner();

    let updated = sqlx::query_as::<_, EmbedPreset>(
        r#"
        UPDATE embed_presets SET
            name        = COALESCE($1, name),
            site_name   = CASE WHEN $2  THEN $3  ELSE site_name END,
            site_url    = CASE WHEN $4  THEN $5  ELSE site_url END,
            author_name = CASE WHEN $6  THEN $7  ELSE author_name END,
            author_url  = CASE WHEN $8  THEN $9  ELSE author_url END,
            title       = CASE WHEN $10 THEN $11 ELSE title END,
            description = CASE WHEN $12 THEN $13 ELSE description END,
            color       = CASE WHEN $14 THEN $15 ELSE color END
        WHERE id = $16 AND user_id = $17
        RETURNING *
        "#,
    )
    .bind(&body.name)
    .bind(site_name_p)
    .bind(&site_name_v)
    .bind(site_url_p)
    .bind(&site_url_v)
    .bind(author_name_p)
    .bind(&author_name_v)
    .bind(author_url_p)
    .bind(&author_url_v)
    .bind(title_p)
    .bind(&title_v)
    .bind(description_p)
    .bind(&description_v)
    .bind(color_p)
    .bind(&color_v)
    .bind(&preset_id)
    .bind(&user.0.id)
    .fetch_optional(&state.db)
    .await
    .map_err(
        MapDbError::new()
            .on_unique_conflict("a preset with that name already exists")
            .build(),
    )?;

    let preset = updated.ok_or_not_found()?;

    Ok(HttpResponse::Ok().json(EmbedPresetResponse::from(preset)))
}
