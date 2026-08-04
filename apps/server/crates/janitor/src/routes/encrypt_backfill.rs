use actix_web::{post, web, HttpResponse};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use futures_util::StreamExt;
use iono_core::{crypto, AppError};
use secrecy::ExposeSecret;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use subtle::ConstantTimeEq;

use crate::state::AppState;

static BACKFILL_RUNNING: AtomicBool = AtomicBool::new(false);

struct RunGuard;

impl Drop for RunGuard {
    fn drop(&mut self) {
        BACKFILL_RUNNING.store(false, Ordering::SeqCst);
    }
}

#[post("/encrypt-backfill")]
pub async fn encrypt_backfill(state: web::Data<AppState>, auth: BearerAuth) -> HttpResponse {
    if !bool::from(
        auth.token()
            .as_bytes()
            .ct_eq(state.maintenance_token.expose_secret().as_bytes()),
    ) {
        return HttpResponse::Unauthorized().json(serde_json::json!({ "error": "unauthorized" }));
    }

    if BACKFILL_RUNNING
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return HttpResponse::Conflict()
            .json(serde_json::json!({ "error": "backfill already running" }));
    }

    let state = state.into_inner();
    state.bg.clone().spawn(async move {
        let _guard = RunGuard;
        let start = Instant::now();
        match run_backfill(&state).await {
            Ok((encrypted, failed)) => tracing::info!(
                encrypted,
                failed,
                elapsed_ms = start.elapsed().as_millis() as u64,
                "encryption backfill finished"
            ),
            Err(e) => tracing::error!(error = %e, "encryption backfill aborted"),
        }
    });

    HttpResponse::Accepted().json(serde_json::json!({ "status": "backfill started" }))
}

async fn run_backfill(state: &AppState) -> Result<(u64, u64), AppError> {
    let key = crypto::parse_key(state.core.config.file_encryption_key.expose_secret())?;
    let (mut encrypted, mut failed) = (0u64, 0u64);

    loop {
        let batch: Vec<(String, String)> = sqlx::query_as(
            "SELECT id, original_name FROM files WHERE encryption_iv IS NULL LIMIT $1",
        )
        .bind(state.core.config.encrypt_backfill_batch_size)
        .fetch_all(&state.core.db)
        .await
        .map_err(AppError::from)?;

        if batch.is_empty() {
            break;
        }

        let mut progressed = false;
        for (id, s3_key) in batch {
            match encrypt_one(state, &key, &s3_key).await {
                Ok(iv) => {
                    sqlx::query("UPDATE files SET encryption_iv = $1 WHERE id = $2")
                        .bind(iv.to_vec())
                        .bind(&id)
                        .execute(&state.core.db)
                        .await
                        .map_err(AppError::from)?;
                    encrypted += 1;
                    progressed = true;
                }
                Err(e) => {
                    tracing::warn!(file_id = %id, error = %e, "could not encrypt object");
                    failed += 1;
                }
            }
        }

        if !progressed {
            break;
        }
    }

    Ok((encrypted, failed))
}

async fn encrypt_one(
    state: &AppState,
    key: &[u8; crypto::KEY_LEN],
    s3_key: &str,
) -> Result<[u8; crypto::IV_LEN], AppError> {
    let object = state.core.storage.get(s3_key, None).await?;

    let mut plaintext = Vec::new();
    let mut stream = object.stream;
    while let Some(chunk) = stream.next().await {
        plaintext.extend_from_slice(&chunk.map_err(AppError::from)?);
    }

    let iv = crypto::random_iv();
    crypto::encrypt_buffer(key, &iv, &mut plaintext)?;

    state
        .core
        .storage
        .save(s3_key, &plaintext, "application/octet-stream")
        .await?;

    Ok(iv)
}
