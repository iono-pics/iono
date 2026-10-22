use actix_web::{web, App, HttpServer};
use std::sync::Mutex;
use tokio::task::JoinHandle;
use tracing_actix_web::TracingLogger;

use iono_core::{cloudflare::CloudflareClient, state::CoreState};

mod routes;
mod state;

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

    let cloudflare = CloudflareClient::new(
        config.cloudflare_zone_id.clone(),
        config.cloudflare_api_token.clone(),
    );

    let state = web::Data::new(AppState {
        core,
        cloudflare,
        maintenance_token,
        bg: bg.handle().clone(),
        sweep_task: Mutex::new(None),
        backfill_task: Mutex::new(None),
    });
    let state_after = state.clone();

    HttpServer::new(move || {
        App::new()
            .wrap(TracingLogger::default())
            .app_data(state.clone())
            .configure(routes::configure)
    })
    .workers(1)
    .bind((host, port))?
    .run()
    .await?;

    drain(&state_after.sweep_task, "sweep").await;
    drain(&state_after.backfill_task, "encryption backfill").await;
    bg.shutdown_background();

    Ok(())
}

async fn drain(slot: &Mutex<Option<JoinHandle<()>>>, name: &str) {
    let task = slot.lock().unwrap().take();
    let Some(task) = task else { return };
    if task.is_finished() {
        return;
    }

    tracing::info!(task = name, "waiting for in flight task to finish");
    if let Err(e) = task.await {
        tracing::error!(task = name, error = %e, "task did not finish cleanly");
    }
}
