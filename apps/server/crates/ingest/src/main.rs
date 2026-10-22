use actix_web::{http::Method, web, App, HttpServer};
use secrecy::ExposeSecret;
use tracing_actix_web::TracingLogger;

mod auth;
mod routes;
mod state;

use state::AppState;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let config = iono_core::bootstrap::init_config();

    let state = AppState::build(&config).await;

    let host = config.host.clone();
    let port = config.ingest_port;

    tracing::info!("iono-ingest listening on http://{}:{}", host, port);

    let state = web::Data::new(state);
    let governor = routes::rate_limit::ingest_governor(&config, config.jwt_secret.expose_secret());

    HttpServer::new(move || {
        let governor = governor.clone();
        let cors = iono_core::web::cors([Method::POST, Method::PUT, Method::DELETE]);
        App::new()
            .wrap(cors)
            .wrap(TracingLogger::default())
            .wrap(actix_web::middleware::NormalizePath::trim())
            .app_data(state.clone())
            .configure(move |cfg| routes::configure(cfg, &governor))
    })
    .bind((host, port))?
    .run()
    .await
}
