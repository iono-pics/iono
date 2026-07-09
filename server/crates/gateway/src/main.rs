use actix_web::{get, App, HttpResponse, HttpServer};
use tracing_actix_web::TracingLogger;

mod error;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    tracing::info!("iono-gateway listening on http://0.0.0.0:8080");

    HttpServer::new(|| App::new().wrap(TracingLogger::default()))
        .bind(("0.0.0.0", 8080))?
        .run()
        .await
}
