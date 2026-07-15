use actix_web::{patch, web, HttpResponse};
use iono_core::AppError;
use serde::Deserialize;
use utoipa::ToSchema;

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
}

impl SelfDestructDuration {
    fn to_seconds(&self) -> i64 {
        match self {
            Self::OneHour => 3_600,
            Self::ThreeHours => 3 * 3_600,
            Self::TwelveHours => 12 * 3_600,
            Self::OneDay => 24 * 3_600,
            Self::ThreeDays => 3 * 24 * 3_600,
            Self::OneWeek => 7 * 24 * 3_600,
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateSettingsRequest {
    default_expires_in_seconds: Option<SelfDestructDuration>,
}

#[utoipa::path(
    patch,
    path = "/user/settings",
    request_body = UpdateSettingsRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "settings updated"),
        (status = 401, description = "missing or invalid token")
    )
)]
#[patch("/settings")]
pub async fn update_settings(
    state: web::Data<AppState>,
    user: JwtUser,
    body: web::Json<UpdateSettingsRequest>,
) -> ApiResult<HttpResponse> {
    let default_expires_in_seconds = body
        .into_inner()
        .default_expires_in_seconds
        .map(|d| d.to_seconds());

    sqlx::query("UPDATE user_settings SET default_expires_in_seconds = $1 WHERE user_id = $2")
        .bind(default_expires_in_seconds)
        .bind(&user.0.id)
        .execute(&state.db)
        .await
        .map_err(AppError::from)?;

    Ok(HttpResponse::Ok().finish())
}
