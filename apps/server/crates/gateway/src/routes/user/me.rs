use actix_web::{get, web, HttpResponse};
use chrono::{DateTime, Utc};
use iono_core::{
    entities::{DisplayNameStyle, Plan, Subscription, SubscriptionStatus, User, UserSettings},
    quota,
    web::ApiResult,
    AppError,
};
use serde::Serialize;
use utoipa::ToSchema;

use crate::{auth::JwtUser, state::AppState};

#[derive(Debug, Serialize, ToSchema)]
pub struct PlanSummary {
    id: String,
    name: String,
    storage_quota_bytes: i64,
    max_upload_bytes: i64,
    expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct StorageSummary {
    used_bytes: i64,
    quota_bytes: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SubscriptionSummary {
    plan_id: String,
    status: SubscriptionStatus,
    current_period_end: Option<DateTime<Utc>>,
    cancel_at_period_end: bool,
}

impl From<Subscription> for SubscriptionSummary {
    fn from(s: Subscription) -> Self {
        Self {
            plan_id: s.plan_id,
            status: s.status,
            current_period_end: s.current_period_end,
            cancel_at_period_end: s.cancel_at_period_end,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SettingsSummary {
    display_name_length: i16,
    display_name_style: DisplayNameStyle,
    display_name_include_extension: bool,
    raw_links_only: bool,
    default_expires_in_seconds: Option<i64>,
    lossless_images: bool,
}

impl From<UserSettings> for SettingsSummary {
    fn from(s: UserSettings) -> Self {
        Self {
            display_name_length: s.display_name_length,
            display_name_style: s.display_name_style,
            display_name_include_extension: s.display_name_include_extension,
            raw_links_only: s.raw_links_only,
            default_expires_in_seconds: s.default_expires_in_seconds,
            lossless_images: s.lossless_images,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct MeResponse {
    id: String,
    username: String,
    email: Option<String>,
    has_password: bool,
    totp_enabled: bool,
    passkey_required: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    plan: PlanSummary,
    storage: StorageSummary,
    subscription: Option<SubscriptionSummary>,
    settings: SettingsSummary,
}

#[utoipa::path(
    get,
    path = "/user/@me",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "the user, their plan, usage, subscription and settings", body = MeResponse),
        (status = 401, description = "missing or invalid token")
    )
)]
#[get("/@me")]
pub async fn me(state: web::Data<AppState>, user: JwtUser) -> ApiResult<HttpResponse> {
    let User {
        id,
        username,
        email,
        password_hash,
        plan_expires_at,
        totp_enabled,
        passkey_required,
        created_at,
        updated_at,
        ..
    } = user.0;

    let plan = quota::plan_for_user(&state.db, &id).await?;
    let used_bytes = quota::storage_used_bytes(&state.db, &id).await?;
    let subscription = current_subscription(&state.db, &id).await?;
    let settings = settings_for_user(&state.db, &id).await?;

    let Plan {
        id: plan_id,
        name: plan_name,
        storage_quota_bytes,
        max_upload_bytes,
        ..
    } = plan;

    Ok(HttpResponse::Ok().json(MeResponse {
        id,
        username,
        email,
        has_password: password_hash.is_some(),
        totp_enabled,
        passkey_required,
        created_at,
        updated_at,
        plan: PlanSummary {
            id: plan_id,
            name: plan_name,
            storage_quota_bytes,
            max_upload_bytes,
            expires_at: plan_expires_at,
        },
        storage: StorageSummary {
            used_bytes,
            quota_bytes: storage_quota_bytes,
        },
        subscription: subscription.map(Into::into),
        settings: settings.into(),
    }))
}

async fn current_subscription(
    db: &sqlx::PgPool,
    user_id: &str,
) -> Result<Option<Subscription>, AppError> {
    sqlx::query_as::<_, Subscription>(
        r#"
        SELECT * FROM subscriptions
        WHERE user_id = $1
        ORDER BY (status IN ('trialing', 'active', 'past_due')) DESC, created_at DESC
        LIMIT 1
        "#,
    )
    .bind(user_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::from)
}

async fn settings_for_user(db: &sqlx::PgPool, user_id: &str) -> Result<UserSettings, AppError> {
    sqlx::query_as::<_, UserSettings>("SELECT * FROM user_settings WHERE user_id = $1")
        .bind(user_id)
        .fetch_optional(db)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::internal("user has no user_settings row"))
}
