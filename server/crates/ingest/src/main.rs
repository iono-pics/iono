use actix_cors::Cors;
use actix_multipart::form::MultipartFormConfig;
use actix_web::{
    get,
    http::{header, Method},
    web, App, HttpServer,
};
use tracing_actix_web::TracingLogger;
use utoipa::OpenApi;

use iono_core::{db, storage, AppError, Config};

mod auth;
mod error;
mod routes;
mod state;

use error::ApiError;
use state::AppState;

#[derive(OpenApi)]
#[openapi(
    info(title = "iono ingest", description = "file uploads"),
    paths(routes::upload::upload_file),
    components(schemas(routes::upload::UploadForm))
)]
struct ApiDoc;

#[get("/openapi.json")]
async fn openapi_spec() -> web::Json<utoipa::openapi::OpenApi> {
    web::Json(ApiDoc::openapi())
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let config = Config::from_env();

    let storage = storage::build(&config)
        .await
        .expect("failed to initialize storage backend");

    let db = db::build(&config)
        .await
        .expect("failed to connect to database");

    let host = config.host.clone();
    let port = config.ingest_port;
    let max_upload = config.max_upload_size_bytes;

    tracing::info!("iono-ingest listening on http://{}:{}", host, port);

    let state = web::Data::new(AppState {
        storage,
        db,
        config,
    });

    HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin()
            .allowed_methods([Method::POST])
            .allowed_headers(vec![header::AUTHORIZATION, header::CONTENT_TYPE])
            .max_age(3600);
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
            .service(routes::upload::upload_file)
            .service(openapi_spec)
    })
    .bind((host, port))?
    .run()
    .await
}
