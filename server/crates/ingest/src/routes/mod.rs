pub mod paste;
pub mod upload;

use actix_web::{get, web};
use iono_core::openapi::BearerSecurity;
use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    info(title = "iono ingest", description = "file and paste uploads"),
    paths(upload::upload_file, paste::create_paste),
    components(schemas(upload::UploadForm, paste::CreatePasteRequest)),
    modifiers(&BearerSecurity)
)]
struct ApiDoc;

#[get("/openapi.json")]
async fn openapi_spec() -> web::Json<utoipa::openapi::OpenApi> {
    web::Json(ApiDoc::openapi())
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(upload::upload_file)
        .service(paste::create_paste)
        .service(openapi_spec);
}
