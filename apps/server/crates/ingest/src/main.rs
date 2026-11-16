use actix_web::{http::Method, web, App, HttpServer};
use iono_core::web::PathOnlyRootSpan;
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
    let parts_governor = routes::rate_limit::parts_governor();
    let proxies = web::Data::new(config.trusted_proxies.clone());

    HttpServer::new(move || {
        let governor = governor.clone();
        let parts_governor = parts_governor.clone();
        let cors = iono_core::web::cors(&config, [Method::POST, Method::PUT, Method::DELETE]);
        App::new()
            .wrap(cors)
            .wrap(iono_core::web::security_headers())
            .wrap(TracingLogger::<PathOnlyRootSpan>::new())
            .wrap(actix_web::middleware::NormalizePath::trim())
            .app_data(state.clone())
            .app_data(proxies.clone())
            .app_data(iono_core::web::json_config(&config))
            .app_data(iono_core::web::payload_config(&config))
            .configure(move |cfg| routes::configure(cfg, &governor, &parts_governor))
    })
    .client_request_timeout(iono_core::web::CLIENT_REQUEST_TIMEOUT)
    .client_disconnect_timeout(iono_core::web::CLIENT_DISCONNECT_TIMEOUT)
    .max_connections(iono_core::web::MAX_CONNECTIONS_PER_WORKER)
    .bind((host, port))?
    .run()
    .await
}
