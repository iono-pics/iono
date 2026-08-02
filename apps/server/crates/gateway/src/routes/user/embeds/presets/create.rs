use actix_web::{post, web, HttpResponse};
use iono_core::{
    entities::EmbedPreset,
    validators,
    web::{ApiResult, MapDbError},
    AppError,
};
use serde::Deserialize;
use utoipa::ToSchema;
use uuid::Uuid;
use validator::Validate;

use crate::{
    auth::AuthedUser, routes::user::embeds::presets::EmbedPresetResponse, state::AppState,
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

    if let Some(site_name) = &body.site_name {
        validators::text_length(site_name, 256, "site_name")?;
    }
    if let Some(author_name) = &body.author_name {
        validators::text_length(author_name, 256, "author_name")?;
    }
    if let Some(title) = &body.title {
        validators::text_length(title, 256, "title")?;
    }
    if let Some(description) = &body.description {
        validators::text_length(description, 1024, "description")?;
    }
    if let Some(site_url) = &body.site_url {
        validators::http_url(site_url, 2048)?;
    }
    if let Some(author_url) = &body.author_url {
        validators::http_url(author_url, 2048)?;
    }
    if let Some(color) = &body.color {
        validators::hex_color(color)?;
    }

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
