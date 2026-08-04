use actix_web::{http::Method, web, App, HttpServer};
use tracing_actix_web::TracingLogger;

use std::sync::Arc;

use iono_core::{
    cloudflare::CloudflareClient,
    db,
    oauth::{OAuthClient, DISCORD_PROVIDER},
    storage,
};
use secrecy::ExposeSecret;

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

    let storage = storage::build(&config)
        .await
        .expect("failed to initialize storage backend");

    let host = config.host.clone();
    let port = config.gateway_port;

    tracing::info!("iono-gateway listening on http://{}:{}", host, port);

    let webauthn = iono_core::auth::webauthn::build_webauthn(
        &config.webauthn_rp_id,
        &config.webauthn_rp_origin,
    )
    .expect("failed to build webauthn config");

    let cloudflare = Arc::new(CloudflareClient::new(
        config.cloudflare_zone_id.clone(),
        config.cloudflare_api_token.clone(),
    ));

    let discord = Arc::new(OAuthClient::new(
        DISCORD_PROVIDER,
        config.discord_client_id.clone(),
        config.discord_client_secret.clone(),
        config.discord_redirect_uri.clone(),
    ));

    let stripe = config
        .stripe_api_key
        .as_ref()
        .map(|k| stripe::Client::new(k.expose_secret()));

    let state = web::Data::new(AppState {
        db,
        storage,
        cloudflare,
        discord,
        stripe,
        config,
        webauthn,
    });

    let governor = routes::rate_limit::auth_governor(&state.config);

    HttpServer::new(move || {
        let governor = governor.clone();
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
            .configure(move |cfg| routes::configure(cfg, &governor))
    })
    .bind((host, port))?
    .run()
    .await
}
