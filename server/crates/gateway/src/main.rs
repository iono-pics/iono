use actix_cors::Cors;
use actix_web::{
    http::{header, Method},
    web, App, HttpServer,
};
use tracing_actix_web::TracingLogger;

use iono_core::{db, Config};

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

    let db = db::build(&config)
        .await
        .expect("failed to connect to database");

    let host = config.host.clone();
    let port = config.gateway_port;

    tracing::info!("iono-gateway listening on http://{}:{}", host, port);

    let state = web::Data::new(AppState { db, config });

    HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin()
            .allowed_methods([
                Method::GET,
                Method::POST,
                Method::PUT,
                Method::PATCH,
                Method::DELETE,
            ])
            .allowed_headers(vec![header::AUTHORIZATION, header::CONTENT_TYPE])
            .max_age(3600);
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
