use actix_web::{get, web, HttpRequest, HttpResponse};

use iono_core::web::ApiResult;

use crate::state::AppState;

use super::{fetch_file_with_prefix, raw_file_inner, ViewQuery};

#[get("/{prefix}/raw/{display_name}")]
pub async fn raw_file_with_prefix(
    state: web::Data<AppState>,
    path: web::Path<(String, String)>,
    query: web::Query<ViewQuery>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    let (prefix, display_name) = path.into_inner();
    let file = fetch_file_with_prefix(&state, &prefix, &display_name).await?;
    raw_file_inner(&state, file, &query, &req).await
}
