use actix_web::{http::Method, web, App, HttpServer};
use tracing_actix_web::TracingLogger;

use iono_core::db;

mod auth;
mod routes;
mod state;
mod webauthn_sessions;

use state::AppState;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let config = iono_core::bootstrap::init_config();

    let db = db::build(&config)
        .await
        .expect("failed to connect to database");

    let host = config.host.clone();
    let port = config.gateway_port;

    tracing::info!("iono-gateway listening on http://{}:{}", host, port);

    let webauthn = iono_core::auth::webauthn::build_webauthn(
        &config.webauthn_rp_id,
        &config.webauthn_rp_origin,
    )
    .expect("failed to build webauthn config");

    let state = web::Data::new(AppState {
        db,
        config,
        webauthn,
    });

    HttpServer::new(move || {
        let cors = iono_core::web::cors([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
        ]);
        App::new()
            .wrap(cors)
            .wrap(TracingLogger::default())
            .wrap(actix_web::middleware::NormalizePath::trim())
            .app_data(state.clone())
            .configure(routes::configure)
    })
    .bind((host, port))?
    .run()
    .await
}
