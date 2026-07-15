use actix_web::{post, web, HttpResponse};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use iono_core::AppError;
use secrecy::ExposeSecret;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use subtle::ConstantTimeEq;

use crate::state::AppState;

const BATCH_SIZE: i64 = 500;

static SWEEP_RUNNING: AtomicBool = AtomicBool::new(false);

struct SweepGuard;

impl Drop for SweepGuard {
    fn drop(&mut self) {
        SWEEP_RUNNING.store(false, Ordering::SeqCst);
    }
}

#[post("/sweep")]
pub async fn sweep(state: web::Data<AppState>, auth: BearerAuth) -> HttpResponse {
    if !bool::from(
        auth.token()
            .as_bytes()
            .ct_eq(state.maintenance_token.expose_secret().as_bytes()),
    ) {
        return HttpResponse::Unauthorized().json(serde_json::json!({ "error": "unauthorized" }));
    }

    if SWEEP_RUNNING
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return HttpResponse::Conflict()
            .json(serde_json::json!({ "error": "sweep already running" }));
    }

    let state = state.into_inner();
    let slot = state.clone();
    let task = state.bg.clone().spawn(async move {
        let _guard = SweepGuard;
        let start = Instant::now();
        match run_sweep(&state).await {
            Ok((deleted, failed)) => {
                tracing::info!(
                    deleted,
                    failed,
                    elapsed_ms = start.elapsed().as_millis() as u64,
                    "sweep finished"
                );
            }
            Err(e) => tracing::error!(error = %e, "sweep aborted"),
        }
    });
    *slot.sweep_task.lock().unwrap() = Some(task);

    HttpResponse::Accepted().json(serde_json::json!({ "status": "sweep started" }))
}

// TODO: also sweep pastes and short links
async fn run_sweep(state: &AppState) -> Result<(u64, u64), AppError> {
    let mut deleted: u64 = 0;
    let mut failed: u64 = 0;
    loop {
        let batch: Vec<(String, String)> = sqlx::query_as(
            r#"
            SELECT id, original_name FROM files
            WHERE expires_at IS NOT NULL AND expires_at < now()
            LIMIT $1
            "#,
        )
        .bind(BATCH_SIZE)
        .fetch_all(&state.db)
        .await?;

        if batch.is_empty() {
            break;
        }

        let keys: Vec<String> = batch.iter().map(|(_, key)| key.clone()).collect();
        let deleted_keys: HashSet<String> = state
            .storage
            .delete_many(&keys)
            .await?
            .into_iter()
            .collect();

        let deleted_ids: Vec<String> = batch
            .iter()
            .filter(|(_, key)| deleted_keys.contains(key))
            .map(|(id, _)| id.clone())
            .collect();

        failed += (batch.len() - deleted_ids.len()) as u64;

        if deleted_ids.is_empty() {
            break;
        }

        sqlx::query("DELETE FROM files WHERE id = ANY($1)")
            .bind(&deleted_ids)
            .execute(&state.db)
            .await?;

        deleted += deleted_ids.len() as u64;
    }

    Ok((deleted, failed))
}
