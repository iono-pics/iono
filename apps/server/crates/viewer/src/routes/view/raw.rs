use actix_web::{get, web, HttpRequest, HttpResponse};

use iono_core::web::ApiResult;

use crate::state::AppState;

use super::{fetch_file, raw_file_inner, ViewQuery};

#[get("/raw/{display_name}")]
pub async fn raw_file(
    state: web::Data<AppState>,
    path: web::Path<String>,
    query: web::Query<ViewQuery>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    let display_name = path.into_inner();
    let file = fetch_file(&state, &display_name).await?;
    raw_file_inner(&state, file, &query, &req).await
}
