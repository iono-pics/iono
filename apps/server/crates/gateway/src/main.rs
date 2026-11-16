use actix_web::{http::Method, web, App, HttpServer};
use tracing_actix_web::TracingLogger;

use std::sync::Arc;

use iono_core::{
    auth::login_throttle::LoginThrottle,
    bootstrap::fatal,
    cloudflare::CloudflareClient,
    db,
    oauth::{OAuthClient, DISCORD_PROVIDER},
    storage,
    web::PathOnlyRootSpan,
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
        .unwrap_or_else(|e| fatal("connect to the database", &e));

    let storage = storage::build(&config)
        .await
        .unwrap_or_else(|e| fatal("initialize the storage backend", &e));

    let host = config.host.clone();
    let port = config.gateway_port;

    tracing::info!("iono-gateway listening on http://{}:{}", host, port);

    let webauthn = iono_core::auth::webauthn::build_webauthn(
        &config.webauthn_rp_id,
        &config.webauthn_rp_origin,
    )
    .unwrap_or_else(|e| fatal("build the webauthn config", &e));

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

    let keyring = config
        .keyring()
        .unwrap_or_else(|e| fatal("build the encryption keyring", &e));

    let state = web::Data::new(AppState {
        keyring,
        db,
        storage,
        cloudflare,
        discord,
        stripe,
        config,
        webauthn,
        login_throttle: LoginThrottle::default(),
    });

    let governor = routes::rate_limit::auth_governor(&state.config);
    let proxies = web::Data::new(state.config.trusted_proxies.clone());

    HttpServer::new(move || {
        let governor = governor.clone();
        let cors = iono_core::web::cors(
            &state.config,
            [
                Method::GET,
                Method::POST,
                Method::PUT,
                Method::PATCH,
                Method::DELETE,
            ],
        );
        App::new()
            .wrap(cors)
            .wrap(iono_core::web::security_headers())
            .wrap(TracingLogger::<PathOnlyRootSpan>::new())
            .wrap(actix_web::middleware::NormalizePath::trim())
            .app_data(state.clone())
            .app_data(proxies.clone())
            .app_data(iono_core::web::json_config(&state.config))
            .app_data(iono_core::web::payload_config(&state.config))
            .configure(move |cfg| routes::configure(cfg, &governor))
    })
    .client_request_timeout(iono_core::web::CLIENT_REQUEST_TIMEOUT)
    .client_disconnect_timeout(iono_core::web::CLIENT_DISCONNECT_TIMEOUT)
    .max_connections(iono_core::web::MAX_CONNECTIONS_PER_WORKER)
    .bind((host, port))?
    .run()
    .await
}
