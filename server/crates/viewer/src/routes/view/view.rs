use actix_web::{get, web, HttpResponse};

use iono_core::web::ApiResult;

use crate::state::AppState;

use super::{fetch_file, view_page_inner, ViewQuery};

#[get("/{display_name}")]
pub async fn view_page(
    state: web::Data<AppState>,
    path: web::Path<String>,
    query: web::Query<ViewQuery>,
) -> ApiResult<HttpResponse> {
    let display_name = path.into_inner();
    let file = fetch_file(&state, &display_name).await?;
    view_page_inner(&state, file, &format!("/raw/{display_name}"), &query).await
}
