use actix_web::{post, web, HttpResponse};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use bytes::Bytes;
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
    let slot = state.clone();
    let task = state.bg.clone().spawn(async move {
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
    *slot.backfill_task.lock().unwrap() = Some(task);

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
            "object above the backfill size limit, skipping"
        );
        return Ok(Outcome::Skipped);
    }

    let mut keystreams = Vec::new();
    if let (Some(iv), Some(version)) = (row.encryption_iv.as_deref(), row.encryption_key_version) {
        keystreams.push(crypto::Keystream::at(
            keyring.get(version)?,
            &iv_array(iv)?,
            0,
        )?);
    }

    let dek = crypto::random_key();
    let encryption_iv = crypto::random_iv();
    keystreams.push(crypto::Keystream::at(&dek, &encryption_iv, 0)?);
    let mut layers = crypto::Layers::new(keystreams);

    let object = state.core.storage.get(&row.original_name, None).await?;
    let body = object.stream.map(move |chunk| {
        let mut buf = chunk.map_err(AppError::from)?.to_vec();
        layers.apply(&mut buf);
        Ok(Bytes::from(buf))
    });

    state
        .core
        .storage
        .save_stream(
            &row.original_name,
            "application/octet-stream",
            Box::pin(body),
        )
        .await?;

    let dek_iv = crypto::random_iv();
    let wrapped_dek = crypto::wrap_key(keyring.current(), &dek_iv, &dek)?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use iono_core::state::CoreState;
    use iono_core::Config;
    use std::sync::Mutex;
    use uuid::Uuid;

    const BIG: usize = 20 * 1024 * 1024;

    async fn state() -> AppState {
        dotenvy::from_path("../../../.env").ok();
        let config = Config::from_env();
        AppState {
            core: CoreState::build(&config).await,
            maintenance_token: secrecy::SecretString::from("test"),
            bg: tokio::runtime::Handle::current(),
            sweep_task: Mutex::new(None),
            backfill_task: Mutex::new(None),
        }
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    async fn read_object(state: &AppState, key: &str) -> Vec<u8> {
        let object = state.core.storage.get(key, None).await.unwrap();
        let mut out = Vec::new();
        let mut body = object.stream;
        while let Some(chunk) = body.next().await {
            out.extend_from_slice(&chunk.unwrap());
        }
        out
    }

    fn row(
        key: &str,
        size: usize,
        encryption_iv: Option<Vec<u8>>,
        version: Option<i16>,
    ) -> PendingRow {
        PendingRow {
            id: Uuid::new_v4().to_string(),
            original_name: key.to_owned(),
            size_bytes: size as i64,
            encryption_key_version: version,
            encryption_iv,
            wrapped_dek: None,
            dek_iv: None,
        }
    }

    fn decrypt(state: &AppState, cipher: &mut [u8], outcome: &Outcome) {
        let Outcome::Converted {
            encryption_iv,
            wrapped_dek,
            dek_iv,
        } = outcome
        else {
            panic!("expected a conversion, got a different outcome");
        };
        let dek =
            crypto::unwrap_key(state.core.keyring.current(), dek_iv, &wrapped_dek[..]).unwrap();
        crypto::Layers::new(vec![crypto::Keystream::at(&dek, encryption_iv, 0).unwrap()])
            .apply(cipher);
    }

    #[tokio::test]
    #[ignore = "needs postgres and a live s3 endpoint"]
    async fn a_plaintext_object_larger_than_a_part_converts_byte_for_byte() {
        let state = state().await;
        let key = format!("backfill-plain-{}", Uuid::new_v4());
        let plain = pattern(BIG);

        state
            .core
            .storage
            .save(&key, &plain, "application/octet-stream")
            .await
            .unwrap();

        let outcome = process(&state, &row(&key, plain.len(), None, None))
            .await
            .expect("process failed");

        let mut stored = read_object(&state, &key).await;
        assert_ne!(stored, plain, "the object was left in the clear");
        decrypt(&state, &mut stored, &outcome);
        assert_eq!(stored, plain, "conversion did not round trip");

        state.core.storage.delete(&key).await.unwrap();
    }

    #[tokio::test]
    #[ignore = "needs postgres and a live s3 endpoint"]
    async fn an_object_under_a_legacy_key_is_re_encrypted_byte_for_byte() {
        let state = state().await;
        let key = format!("backfill-legacy-{}", Uuid::new_v4());
        let plain = pattern(BIG);

        let version = state.core.keyring.current_version();
        let legacy_iv = crypto::random_iv();
        let mut legacy = plain.clone();
        crypto::encrypt_buffer(
            state.core.keyring.get(version).unwrap(),
            &legacy_iv,
            &mut legacy,
        )
        .unwrap();

        state
            .core
            .storage
            .save(&key, &legacy, "application/octet-stream")
            .await
            .unwrap();

        let outcome = process(
            &state,
            &row(&key, legacy.len(), Some(legacy_iv.to_vec()), Some(version)),
        )
        .await
        .expect("process failed");

        let mut stored = read_object(&state, &key).await;
        assert_ne!(stored, plain);
        assert_ne!(stored, legacy, "the object was not re-encrypted");
        decrypt(&state, &mut stored, &outcome);
        assert_eq!(stored, plain, "the legacy layer was not peeled off");

        state.core.storage.delete(&key).await.unwrap();
    }

    #[tokio::test]
    #[ignore = "needs postgres and a live s3 endpoint"]
    async fn an_empty_object_converts_without_error() {
        let state = state().await;
        let key = format!("backfill-empty-{}", Uuid::new_v4());

        state
            .core
            .storage
            .save(&key, &[], "application/octet-stream")
            .await
            .unwrap();

        process(&state, &row(&key, 0, None, None))
            .await
            .expect("process failed");
        assert!(read_object(&state, &key).await.is_empty());

        state.core.storage.delete(&key).await.unwrap();
    }
}
