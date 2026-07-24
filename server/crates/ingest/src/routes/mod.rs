pub mod link;
pub mod paste;
pub mod upload;

use actix_web::{get, web};
use iono_core::openapi::BearerSecurity;
use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    info(title = "iono ingest", description = "file, paste and short link creation"),
    paths(
        upload::upload_file,
        paste::create_paste,
        link::create_short_link
    ),
    components(schemas(
        upload::UploadForm,
        paste::CreatePasteRequest,
        link::CreateShortLinkRequest
    )),
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
        .service(link::create_short_link)
        .service(openapi_spec);
}
