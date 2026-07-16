pub mod upload;

use actix_web::{get, web};
use iono_core::openapi::BearerSecurity;
use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    info(title = "iono ingest", description = "file uploads"),
    paths(upload::upload_file),
    components(schemas(upload::UploadForm)),
    modifiers(&BearerSecurity)
)]
struct ApiDoc;

#[get("/openapi.json")]
async fn openapi_spec() -> web::Json<utoipa::openapi::OpenApi> {
    web::Json(ApiDoc::openapi())
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(upload::upload_file).service(openapi_spec);
}
