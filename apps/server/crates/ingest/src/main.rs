use actix_multipart::form::MultipartFormConfig;
use actix_web::{http::Method, web, App, HttpServer};
use tracing_actix_web::TracingLogger;

use iono_core::AppError;

mod auth;
mod routes;
mod state;

use iono_core::web::ApiError;
use state::AppState;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let config = iono_core::bootstrap::init_config();

    let state = AppState::build(&config).await;

    let host = config.host.clone();
    let port = config.ingest_port;
    let max_upload = config.max_upload_size_bytes;

    tracing::info!("iono-ingest listening on http://{}:{}", host, port);

    let state = web::Data::new(state);

    HttpServer::new(move || {
        let cors = iono_core::web::cors([Method::POST]);
        App::new()
            .wrap(cors)
            .wrap(TracingLogger::default())
            .wrap(actix_web::middleware::NormalizePath::trim())
            .app_data(state.clone())
            .app_data(
                MultipartFormConfig::default()
                    .total_limit(max_upload)
                    .memory_limit(max_upload)
                    .error_handler(|err, _req| {
                        ApiError(AppError::BadRequest(err.to_string())).into()
                    }),
            )
            .configure(routes::configure)
    })
    .bind((host, port))?
    .run()
    .await
}
