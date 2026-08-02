use actix_web::{get, web, HttpResponse};
use iono_core::{quota, web::ApiResult};
use serde::Serialize;
use utoipa::ToSchema;

use crate::{auth::AuthedUser, state::AppState};

#[derive(Debug, Serialize, ToSchema)]
pub struct StorageUsage {
    used_bytes: i64,
    quota_bytes: i64,
    max_upload_bytes: i64,
    plan_name: String,
}

#[utoipa::path(
    get,
    path = "/user/storage",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "current storage usage and quota", body = StorageUsage),
        (status = 401, description = "missing or invalid token"),
    )
)]
#[get("/storage")]
pub async fn get_storage(state: web::Data<AppState>, user: AuthedUser) -> ApiResult<HttpResponse> {
    let plan = quota::plan_for_user(&state.db, &user.0.id).await?;
    let used_bytes = quota::storage_used_bytes(&state.db, &user.0.id).await?;

    Ok(HttpResponse::Ok().json(StorageUsage {
        used_bytes,
        quota_bytes: plan.storage_quota_bytes,
        max_upload_bytes: plan.max_upload_bytes,
        plan_name: plan.name,
    }))
}
