use actix_web::{post, web, HttpResponse};
use iono_core::{
    entities::EmbedPreset,
    web::{ApiResult, MapDbError},
    AppError,
};
use serde::Deserialize;
use utoipa::ToSchema;
use uuid::Uuid;
use validator::Validate;

use crate::{
    auth::AuthedUser,
    routes::user::embeds::presets::{EmbedPresetResponse, PresetFields},
    state::AppState,
};

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct CreateEmbedPresetRequest {
    #[validate(length(min = 1, max = 64, message = "must be 1-64 characters"))]
    name: String,
    site_name: Option<String>,
    site_url: Option<String>,
    author_name: Option<String>,
    author_url: Option<String>,
    title: Option<String>,
    description: Option<String>,
    color: Option<String>,
}

#[utoipa::path(
    post,
    path = "/user/embeds/presets",
    request_body = CreateEmbedPresetRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 201, description = "preset created", body = EmbedPresetResponse),
        (status = 400, description = "validation failed"),
        (status = 401, description = "missing or invalid token"),
        (status = 409, description = "a preset with that name already exists"),
    )
)]
#[post("/embeds/presets")]
pub async fn create_embed_preset(
    state: web::Data<AppState>,
    user: AuthedUser,
    body: web::Json<CreateEmbedPresetRequest>,
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

    let id = Uuid::new_v4().to_string();

    let preset = sqlx::query_as::<_, EmbedPreset>(
        r#"
        INSERT INTO embed_presets (
            id, user_id, name, site_name, site_url,
            author_name, author_url, title, description, color
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(&user.0.id)
    .bind(&body.name)
    .bind(&body.site_name)
    .bind(&body.site_url)
    .bind(&body.author_name)
    .bind(&body.author_url)
    .bind(&body.title)
    .bind(&body.description)
    .bind(&body.color)
    .fetch_one(&state.db)
    .await
    .map_err(
        MapDbError::new()
            .on_unique_conflict("a preset with that name already exists")
            .build(),
    )?;

    Ok(HttpResponse::Created().json(EmbedPresetResponse::from(preset)))
}
