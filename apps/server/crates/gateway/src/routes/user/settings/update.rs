use actix_web::{patch, web, HttpResponse};
use iono_core::{entities::DisplayNameStyle, AppError};
use serde::Deserialize;
use utoipa::ToSchema;
use validator::Validate;

use iono_core::web::ApiResult;

use crate::{auth::JwtUser, state::AppState};

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SelfDestructDuration {
    OneHour,
    ThreeHours,
    TwelveHours,
    OneDay,
    ThreeDays,
    OneWeek,
    Never,
}

impl SelfDestructDuration {
    fn to_seconds(&self) -> Option<i64> {
        match self {
            Self::OneHour => Some(3_600),
            Self::ThreeHours => Some(3 * 3_600),
            Self::TwelveHours => Some(12 * 3_600),
            Self::OneDay => Some(24 * 3_600),
            Self::ThreeDays => Some(3 * 24 * 3_600),
            Self::OneWeek => Some(7 * 24 * 3_600),
            Self::Never => None,
        }
    }
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct UpdateSettingsRequest {
    #[validate(range(min = 16, max = 32, message = "must be between 16 and 32"))]
    display_name_length: Option<i16>,
    display_name_style: Option<DisplayNameStyle>,
    display_name_include_extension: Option<bool>,
    raw_links_only: Option<bool>,
    default_expires_in_seconds: Option<SelfDestructDuration>,
    lossless_images: Option<bool>,
}

#[utoipa::path(
    patch,
    path = "/user/settings",
    request_body = UpdateSettingsRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "settings updated"),
        (status = 400, description = "validation failed"),
        (status = 401, description = "missing or invalid token")
    )
)]
#[patch("/settings")]
pub async fn update_settings(
    state: web::Data<AppState>,
    user: JwtUser,
    body: web::Json<UpdateSettingsRequest>,
) -> ApiResult<HttpResponse> {
    body.validate()
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    let body = body.into_inner();
    let expires_provided = body.default_expires_in_seconds.is_some();

    if body.display_name_length.is_none()
        && body.display_name_style.is_none()
        && body.display_name_include_extension.is_none()
        && body.raw_links_only.is_none()
        && !expires_provided
        && body.lossless_images.is_none()
    {
        return Err(AppError::BadRequest("no settings fields provided".into()).into());
    }

    let expires_seconds = body
        .default_expires_in_seconds
        .as_ref()
        .and_then(SelfDestructDuration::to_seconds);

    let result = sqlx::query(
        r#"
        UPDATE user_settings SET
            display_name_length = COALESCE($1, display_name_length),
            display_name_style = COALESCE($2, display_name_style),
            display_name_include_extension = COALESCE($3, display_name_include_extension),
            raw_links_only = COALESCE($4, raw_links_only),
            default_expires_in_seconds = CASE WHEN $5 THEN $6 ELSE default_expires_in_seconds END,
            lossless_images = COALESCE($7, lossless_images)
        WHERE user_id = $8
        "#,
    )
    .bind(body.display_name_length)
    .bind(body.display_name_style)
    .bind(body.display_name_include_extension)
    .bind(body.raw_links_only)
    .bind(expires_provided)
    .bind(expires_seconds)
    .bind(body.lossless_images)
    .bind(&user.0.id)
    .execute(&state.db)
    .await
    .map_err(AppError::from)?;

    if result.rows_affected() == 0 {
        return Err(AppError::internal("user has no settings row to update").into());
    }

    Ok(HttpResponse::Ok().finish())
}
