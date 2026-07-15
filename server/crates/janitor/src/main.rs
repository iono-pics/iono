use actix_web::{web, App, HttpServer};
use std::sync::Mutex;
use tracing_actix_web::TracingLogger;

use iono_core::state::CoreState;

mod state;
mod sweep;

use state::AppState;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let config = iono_core::bootstrap::init_config();

    let maintenance_token = config
        .maintenance_token
        .clone()
        .expect("MAINTENANCE_TOKEN must be set");

    let core = CoreState::build(&config).await;

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
        core,
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
