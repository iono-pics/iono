use actix_governor::{Governor, GovernorConfigBuilder};
use actix_web::{web, App, HttpServer};
use std::sync::Mutex;
use tokio::task::JoinHandle;
use tracing_actix_web::TracingLogger;

use iono_core::{
    bootstrap::fatal, cloudflare::CloudflareClient, state::CoreState, web::PathOnlyRootSpan,
};

mod routes;
mod state;

use state::AppState;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let config = iono_core::bootstrap::init_config();

    let Some(maintenance_token) = config.maintenance_token.clone() else {
        fatal("read the configuration", &"MAINTENANCE_TOKEN must be set");
    };

    let core = CoreState::build(&config).await;

    let host = config.host.clone();
    let port = config.janitor_port;

    // sweeps run here instead of on the actix workers so a graceful
    // shutdown can't cancel one mid-run
    let bg = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap_or_else(|e| fatal("build the background runtime", &e));

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

    let governor = GovernorConfigBuilder::default()
        .seconds_per_request(1)
        .burst_size(5)
        .finish()
        .unwrap_or_else(|| fatal("build the janitor rate limiter", &"invalid rate limit"));

    HttpServer::new(move || {
        App::new()
            .wrap(Governor::new(&governor))
            .wrap(iono_core::web::security_headers())
            .wrap(TracingLogger::<PathOnlyRootSpan>::new())
            .app_data(state.clone())
            .configure(routes::configure)
    })
    .client_request_timeout(iono_core::web::CLIENT_REQUEST_TIMEOUT)
    .client_disconnect_timeout(iono_core::web::CLIENT_DISCONNECT_TIMEOUT)
    .max_connections(iono_core::web::MAX_CONNECTIONS_PER_WORKER)
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
    // the slot only holds a handle, so a poisoned lock is still safe to use
    let task = slot
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    let Some(task) = task else { return };
    if task.is_finished() {
        return;
    }

    tracing::info!(task = name, "waiting for in flight task to finish");
    if let Err(e) = task.await {
        tracing::error!(task = name, error = %e, "task did not finish cleanly");
    }
}
