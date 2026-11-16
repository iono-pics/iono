use actix_web::{web, App, HttpServer};
use iono_core::web::PathOnlyRootSpan;
use tracing_actix_web::TracingLogger;

mod cache;
mod csp;
mod embed;
mod routes;
mod state;
mod unlock;

use state::AppState;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let config = iono_core::bootstrap::init_config();

    let state = AppState::build(&config).await;

    let host = config.host.clone();
    let port = config.viewer_port;

    tracing::info!("iono-viewer listening on http://{}:{}", host, port);

    let state = web::Data::new(state);
    let proxies = web::Data::new(config.trusted_proxies.clone());

    HttpServer::new(move || {
        App::new()
            .wrap(iono_core::web::baseline_headers())
            .wrap(TracingLogger::<PathOnlyRootSpan>::new())
            .app_data(state.clone())
            .app_data(proxies.clone())
            .configure(routes::configure)
    })
    .client_request_timeout(iono_core::web::CLIENT_REQUEST_TIMEOUT)
    .client_disconnect_timeout(iono_core::web::CLIENT_DISCONNECT_TIMEOUT)
    .max_connections(iono_core::web::MAX_CONNECTIONS_PER_WORKER)
    .bind((host, port))?
    .run()
    .await
}
