pub mod link;
pub mod paste;
pub mod rate_limit;
pub mod upload;
pub mod upload_session;

use actix_governor::Governor;
use actix_web::{get, web};
use iono_core::openapi::BearerSecurity;
use utoipa::OpenApi;

use crate::routes::rate_limit::{IngestGovernor, PartsGovernor};

#[derive(OpenApi)]
#[openapi(
    info(title = "iono ingest", description = "file, paste and short link creation"),
    paths(
        upload::upload_file,
        upload_session::create_upload_session,
        upload_session::upload_part,
        upload_session::complete_upload_session,
        upload_session::abort_upload_session,
        paste::create_paste,
        link::create_short_link
    ),
    components(schemas(
        upload::UploadForm,
        upload_session::CreateUploadSessionRequest,
        upload_session::UploadSessionResponse,
        upload_session::CompleteUploadSessionRequest,
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

pub fn configure(
    cfg: &mut web::ServiceConfig,
    governor: &IngestGovernor,
    parts_governor: &PartsGovernor,
) {
    // a 10GB file is 640 parts, so they use an address limiter with a high
    // rate. each is bounded by a session the governed create call had to open
    cfg.service(openapi_spec)
        .service(
            web::resource("/uploads/{id}/parts/{part_number}")
                .wrap(Governor::new(parts_governor))
                .route(web::put().to(upload_session::upload_part)),
        )
        .service(
            web::scope("")
                .wrap(Governor::new(governor))
                .service(upload::upload_file)
                .service(upload_session::create_upload_session)
                .service(upload_session::complete_upload_session)
                .service(upload_session::abort_upload_session)
                .service(paste::create_paste)
                .service(link::create_short_link),
        );
}
