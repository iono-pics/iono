use actix_web::{App, HttpServer};
use tracing_actix_web::TracingLogger;

use iono_core::Config;

mod error;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let config = Config::from_env();

    tracing::info!(
        "{}",
        format!(
            "iono-gateway listening on http://{}:{}",
            config.host, config.gateway_port
        )
    );

    HttpServer::new(|| App::new().wrap(TracingLogger::default()))
        .bind((config.host, config.gateway_port))?
        .run()
        .await
}
