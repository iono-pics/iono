use actix_web::{get, web, HttpResponse};

use iono_core::web::ApiResult;

use crate::state::AppState;

use super::{fetch_file_with_prefix, view_page_inner, ViewQuery};

#[get("/{prefix}/{display_name}")]
pub async fn view_page_with_prefix(
    state: web::Data<AppState>,
    path: web::Path<(String, String)>,
    query: web::Query<ViewQuery>,
) -> ApiResult<HttpResponse> {
    let (prefix, display_name) = path.into_inner();
    let file = fetch_file_with_prefix(&state, &prefix, &display_name).await?;
    view_page_inner(
        &state,
        file,
        &format!("/{prefix}/raw/{display_name}"),
        &query,
    )
    .await
}
