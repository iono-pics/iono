use actix_web::{web, App, HttpServer};
use std::sync::Mutex;
use tracing_actix_web::TracingLogger;

use iono_core::{db, storage, Config};

mod state;
mod sweep;

use state::AppState;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_ansi(false)
        .init();

    let config = Config::from_env();

    let maintenance_token = config
        .maintenance_token
        .clone()
        .expect("MAINTENANCE_TOKEN must be set");

    let storage = storage::build(&config)
        .await
        .expect("failed to initialize storage backend");

    let db = db::build(&config)
        .await
        .expect("failed to connect to database");

    let host = config.host.clone();
    let port = config.janitor_port;

    // sweeps run here instead of on the actix workers so a graceful
    // shutdown can't cancel one mid-run
    let bg = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .expect("failed to build background runtime");

    tracing::info!("iono-janitor listening on http://{}:{}", host, port);

    let state = web::Data::new(AppState {
        storage,
        db,
        maintenance_token,
        bg: bg.handle().clone(),
        sweep_task: Mutex::new(None),
    });
    let state_after = state.clone();

    HttpServer::new(move || {
        App::new()
            .wrap(TracingLogger::default())
            .app_data(state.clone())
            .service(sweep::sweep)
    })
    .workers(1)
    .bind((host, port))?
    .run()
    .await?;

    let task = state_after.sweep_task.lock().unwrap().take();
    if let Some(task) = task {
        if !task.is_finished() {
            tracing::info!("waiting for in-flight sweep to finish");
            let _ = task.await;
        }
    }
    bg.shutdown_background();

    Ok(())
}
