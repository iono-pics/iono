use actix_web::{web, App, HttpServer};
use tracing_actix_web::TracingLogger;

use iono_core::{db, storage, Config};

mod auth;
mod error;
mod routes;
mod state;

use state::AppState;

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

    tracing::info!("iono-ingest listening on http://{}:{}", host, port);

    let state = web::Data::new(AppState {
        storage,
        db,
        config,
    });

    HttpServer::new(move || {
        App::new()
            .wrap(TracingLogger::default())
            .app_data(state.clone())
            .service(routes::upload::upload_file)
    })
    .bind((host, port))?
    .run()
    .await
}
