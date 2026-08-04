use actix_web::{post, web, HttpResponse};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use futures_util::StreamExt;
use iono_core::{crypto, AppError};
use secrecy::ExposeSecret;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use subtle::ConstantTimeEq;

use crate::state::AppState;

#[derive(sqlx::FromRow)]
struct PendingRow {
    id: String,
    original_name: String,
    size_bytes: i64,
    encryption_key_version: Option<i16>,
    encryption_iv: Option<Vec<u8>>,
    wrapped_dek: Option<Vec<u8>>,
    dek_iv: Option<Vec<u8>>,
}

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
            Ok(report) => tracing::info!(
                converted = report.converted,
                rewrapped = report.rewrapped,
                skipped = report.skipped,
                failed = report.failed,
                elapsed_ms = start.elapsed().as_millis() as u64,
                "encryption backfill finished"
            ),
            Err(e) => tracing::error!(error = %e, "encryption backfill aborted"),
        }
    });

    HttpResponse::Accepted().json(serde_json::json!({ "status": "backfill started" }))
}

#[derive(Default)]
struct Report {
    converted: u64,
    rewrapped: u64,
    skipped: u64,
    failed: u64,
}

async fn run_backfill(state: &AppState) -> Result<Report, AppError> {
    let current = state.core.keyring.current_version();
    let mut report = Report::default();

    loop {
        let batch: Vec<PendingRow> = sqlx::query_as(
            r#"
            SELECT id, original_name, size_bytes, encryption_key_version,
                   encryption_iv, wrapped_dek, dek_iv
            FROM files
            WHERE encryption_iv IS NULL
               OR wrapped_dek IS NULL
               OR encryption_key_version IS DISTINCT FROM $1
            LIMIT $2
            "#,
        )
        .bind(current)
        .bind(state.core.config.encrypt_backfill_batch_size)
        .fetch_all(&state.core.db)
        .await
        .map_err(AppError::from)?;

        if batch.is_empty() {
            break;
        }

        let mut progressed = false;
        for row in batch {
            match process(state, &row).await {
                Ok(Outcome::Rewrapped {
                    wrapped_dek,
                    dek_iv,
                }) => {
                    sqlx::query(
                        r#"
                        UPDATE files
                        SET wrapped_dek = $1, dek_iv = $2, encryption_key_version = $3
                        WHERE id = $4
                        "#,
                    )
                    .bind(wrapped_dek.to_vec())
                    .bind(dek_iv.to_vec())
                    .bind(current)
                    .bind(&row.id)
                    .execute(&state.core.db)
                    .await
                    .map_err(AppError::from)?;
                    report.rewrapped += 1;
                    progressed = true;
                }
                Ok(Outcome::Converted {
                    encryption_iv,
                    wrapped_dek,
                    dek_iv,
                }) => {
                    sqlx::query(
                        r#"
                        UPDATE files
                        SET encryption_iv = $1, wrapped_dek = $2, dek_iv = $3,
                            encryption_key_version = $4
                        WHERE id = $5
                        "#,
                    )
                    .bind(encryption_iv.to_vec())
                    .bind(wrapped_dek.to_vec())
                    .bind(dek_iv.to_vec())
                    .bind(current)
                    .bind(&row.id)
                    .execute(&state.core.db)
                    .await
                    .map_err(AppError::from)?;
                    report.converted += 1;
                    progressed = true;
                }
                Ok(Outcome::Skipped) => report.skipped += 1,
                Err(e) => {
                    tracing::warn!(file_id = %row.id, error = %e, "could not encrypt object");
                    report.failed += 1;
                }
            }
        }

        if !progressed {
            break;
        }
    }

    Ok(report)
}

enum Outcome {
    Rewrapped {
        wrapped_dek: [u8; crypto::KEY_LEN],
        dek_iv: [u8; crypto::IV_LEN],
    },
    Converted {
        encryption_iv: [u8; crypto::IV_LEN],
        wrapped_dek: [u8; crypto::KEY_LEN],
        dek_iv: [u8; crypto::IV_LEN],
    },
    Skipped,
}

async fn process(state: &AppState, row: &PendingRow) -> Result<Outcome, AppError> {
    let keyring = &state.core.keyring;

    if let (Some(wrapped), Some(dek_iv), Some(version)) = (
        row.wrapped_dek.as_deref(),
        row.dek_iv.as_deref(),
        row.encryption_key_version,
    ) {
        let dek = crypto::unwrap_key(keyring.get(version)?, &iv_array(dek_iv)?, wrapped)?;
        let dek_iv = crypto::random_iv();
        return Ok(Outcome::Rewrapped {
            wrapped_dek: crypto::wrap_key(keyring.current(), &dek_iv, &dek)?,
            dek_iv,
        });
    }

    let max = state.core.config.encrypt_backfill_max_object_bytes;
    if row.size_bytes > max {
        tracing::warn!(
            file_id = %row.id,
            size_bytes = row.size_bytes,
            max,
            "object too large to convert in memory, skipping"
        );
        return Ok(Outcome::Skipped);
    }

    let object = state.core.storage.get(&row.original_name, None).await?;
    let mut bytes = Vec::with_capacity(row.size_bytes.max(0) as usize);
    let mut stream = object.stream;
    while let Some(chunk) = stream.next().await {
        bytes.extend_from_slice(&chunk.map_err(AppError::from)?);
    }

    if let (Some(iv), Some(version)) = (row.encryption_iv.as_deref(), row.encryption_key_version) {
        crypto::encrypt_buffer(keyring.get(version)?, &iv_array(iv)?, &mut bytes)?;
    }

    let dek = crypto::random_key();
    let encryption_iv = crypto::random_iv();
    crypto::encrypt_buffer(&dek, &encryption_iv, &mut bytes)?;

    let dek_iv = crypto::random_iv();
    let wrapped_dek = crypto::wrap_key(keyring.current(), &dek_iv, &dek)?;

    state
        .core
        .storage
        .save(&row.original_name, &bytes, "application/octet-stream")
        .await?;

    Ok(Outcome::Converted {
        encryption_iv,
        wrapped_dek,
        dek_iv,
    })
}

fn iv_array(iv: &[u8]) -> Result<[u8; crypto::IV_LEN], AppError> {
    iv.try_into()
        .map_err(|_| AppError::internal("stored encryption iv is malformed"))
}
