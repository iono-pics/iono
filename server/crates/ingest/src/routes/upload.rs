use actix_multipart::Multipart;
use actix_web::{post, web, HttpResponse};

use crate::{error::ApiResult, state::AppState};

#[post("/upload")]
pub async fn upload_file(
    _state: web::Data<AppState>,
    mut _payload: Multipart,
) -> ApiResult<HttpResponse> {
    Ok(HttpResponse::Created().json(serde_json::json!({ "url": "url" })))
}
