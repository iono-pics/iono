//! brings stored files up to the current encryption. plaintext and ctr objects
//! are rewritten as format 2, and data keys are rewrapped under the current kek
//! with the authenticated wrap. a ctr file with a user key cannot be rewritten
//! without that key, so it only gets its envelope rewrapped

use actix_web::{post, web, HttpResponse};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use bytes::Bytes;
use futures_util::StreamExt;
use iono_core::{
    crypto,
    deletion::{self, Deleter, Pending},
    AppError,
};
use secrecy::ExposeSecret;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use subtle::ConstantTimeEq;
use uuid::Uuid;

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
    encryption_format: i16,
    has_user_key: bool,
}

impl PendingRow {
    fn rewritable(&self) -> bool {
        self.encryption_iv.is_none()
            || (self.encryption_format == crypto::FORMAT_CTR && !self.has_user_key)
    }
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
    let max_object = state.core.config.encrypt_backfill_max_object_bytes;
    let mut report = Report::default();

    loop {
        // objects over the size limit are left out here so they cannot fill
        // every batch, they are counted as skipped at the end instead
        let batch: Vec<PendingRow> = sqlx::query_as(
            r#"
            SELECT id, original_name, size_bytes, encryption_key_version,
                   encryption_iv, wrapped_dek, dek_iv, encryption_format,
                   user_key_hash IS NOT NULL AS has_user_key
            FROM files
            WHERE ((encryption_iv IS NULL OR (encryption_format = 1 AND user_key_hash IS NULL))
                    AND size_bytes <= $3)
               OR (wrapped_dek IS NOT NULL
                    AND (encryption_key_version IS DISTINCT FROM $1 OR octet_length(wrapped_dek) <> 48))
            ORDER BY id
            LIMIT $2
            "#,
        )
        .bind(current)
        .bind(state.core.config.encrypt_backfill_batch_size)
        .bind(max_object)
        .fetch_all(&state.core.db)
        .await
        .map_err(AppError::from)?;

        if batch.is_empty() {
            break;
        }

        let mut progressed = false;
        for row in batch {
            let result = match process(state, &row).await {
                Ok(outcome) => apply(state, &row, outcome).await,
                Err(e) => Err(e),
            };
            match result {
                Ok(Applied::Converted) => {
                    report.converted += 1;
                    progressed = true;
                }
                Ok(Applied::Rewrapped) => {
                    report.rewrapped += 1;
                    progressed = true;
                }
                Ok(Applied::Gone) => progressed = true,
                Err(e) => {
                    tracing::warn!(file_id = %row.id, error = %e, "could not bring file up to date");
                    report.failed += 1;
                }
            }
        }

        if !progressed {
            break;
        }
    }

    let oversized: i64 = sqlx::query_scalar(
        r#"
        SELECT count(*) FROM files
        WHERE (encryption_iv IS NULL OR (encryption_format = 1 AND user_key_hash IS NULL))
          AND size_bytes > $1
        "#,
    )
    .bind(max_object)
    .fetch_one(&state.core.db)
    .await
    .map_err(AppError::from)?;
    if oversized > 0 {
        tracing::warn!(
            count = oversized,
            max_object,
            "objects above the backfill size limit were not rewritten"
        );
    }
    report.skipped = oversized as u64;

    Ok(report)
}

enum Outcome {
    Rewrapped {
        wrapped_dek: Vec<u8>,
        dek_iv: Vec<u8>,
    },
    Converted {
        new_key: String,
        encryption_iv: [u8; crypto::IV_LEN],
        wrapped_dek: Vec<u8>,
        dek_iv: Vec<u8>,
    },
}

enum Applied {
    Converted,
    Rewrapped,
    /// the file was deleted or changed while we worked, nothing to record
    Gone,
}

async fn process(state: &AppState, row: &PendingRow) -> Result<Outcome, AppError> {
    let keyring = &state.core.keyring;
    let aad = crypto::file_key_aad(&row.id);

    if !row.rewritable() {
        let (Some(wrapped), Some(nonce), Some(version)) = (
            row.wrapped_dek.as_deref(),
            row.dek_iv.as_deref(),
            row.encryption_key_version,
        ) else {
            return Err(AppError::internal(
                "file selected for rewrap has no envelope",
            ));
        };
        let dek = crypto::open_key(keyring.get(version)?, nonce, wrapped, &aad)?;
        let (wrapped_dek, dek_iv) = crypto::seal_key(keyring.current(), &dek, &aad)?;
        return Ok(Outcome::Rewrapped {
            wrapped_dek,
            dek_iv,
        });
    }

    // peel whatever ctr layer the object has now: none, the kek directly
    // (oldest), or an envelope data key
    let mut legacy = Vec::new();
    if let (Some(iv), Some(version)) = (row.encryption_iv.as_deref(), row.encryption_key_version) {
        let kek = keyring.get(version)?;
        let key = match (row.wrapped_dek.as_deref(), row.dek_iv.as_deref()) {
            (Some(wrapped), Some(nonce)) => crypto::open_key(kek, nonce, wrapped, &aad)?,
            _ => *kek,
        };
        legacy.push(crypto::Keystream::at(&key, &iv_array(iv)?, 0)?);
    }
    let legacy = crypto::Layers::new(legacy);

    let dek = crypto::random_key();
    let encryption_iv = crypto::random_iv();
    let sealer = crypto::Sealer::new(&crypto::content_key(&dek, &encryption_iv, None));

    let object = state.core.storage.get(&row.original_name, None).await?;
    let seen = Arc::new(AtomicU64::new(0));
    let counted = seen.clone();
    let body = futures_util::stream::unfold(Some((object.stream, legacy, sealer)), move |st| {
        let counted = counted.clone();
        async move {
            let (mut inner, mut legacy, mut sealer) = st?;
            loop {
                match inner.next().await {
                    Some(Ok(chunk)) => {
                        counted.fetch_add(chunk.len() as u64, Ordering::SeqCst);
                        let mut buf = chunk.to_vec();
                        legacy.apply(&mut buf);
                        match sealer.push(&buf) {
                            Ok(sealed) if sealed.is_empty() => continue,
                            Ok(sealed) => {
                                return Some((
                                    Ok(Bytes::from(sealed)),
                                    Some((inner, legacy, sealer)),
                                ))
                            }
                            Err(e) => return Some((Err(e), None)),
                        }
                    }
                    Some(Err(e)) => return Some((Err(AppError::from(e)), None)),
                    None => return Some((sealer.finish().map(Bytes::from), None)),
                }
            }
        }
    });

    // a new object, so the old one stays readable until the row points away
    // from it. overwriting in place loses the file if the row update fails
    let new_key = replacement_key(&row.original_name);
    state
        .core
        .storage
        .save_stream(&new_key, "application/octet-stream", Box::pin(body))
        .await?;

    // format 2 finds its segment boundaries from size_bytes, so a row that
    // disagrees with its object would make the file unreadable
    let seen = seen.load(Ordering::SeqCst);
    if seen != row.size_bytes as u64 {
        let queued = deletion::enqueue(&state.core.db, &[Pending::object(new_key)]).await?;
        Deleter {
            db: &state.core.db,
            storage: state.core.storage.as_ref(),
            cloudflare: &state.cloudflare,
        }
        .process_ids(&queued)
        .await?;
        return Err(AppError::internal(format!(
            "object holds {seen} bytes but the row says {}",
            row.size_bytes
        )));
    }

    let (wrapped_dek, dek_iv) = crypto::seal_key(keyring.current(), &dek, &aad)?;
    Ok(Outcome::Converted {
        new_key,
        encryption_iv,
        wrapped_dek,
        dek_iv,
    })
}

async fn apply(state: &AppState, row: &PendingRow, outcome: Outcome) -> Result<Applied, AppError> {
    let current = state.core.keyring.current_version();
    match outcome {
        Outcome::Rewrapped {
            wrapped_dek,
            dek_iv,
        } => {
            let updated = sqlx::query(
                r#"
                UPDATE files
                SET wrapped_dek = $1, dek_iv = $2, encryption_key_version = $3
                WHERE id = $4 AND wrapped_dek = $5
                "#,
            )
            .bind(&wrapped_dek)
            .bind(&dek_iv)
            .bind(current)
            .bind(&row.id)
            .bind(&row.wrapped_dek)
            .execute(&state.core.db)
            .await?
            .rows_affected();
            Ok(if updated == 1 {
                Applied::Rewrapped
            } else {
                Applied::Gone
            })
        }
        Outcome::Converted {
            new_key,
            encryption_iv,
            wrapped_dek,
            dek_iv,
        } => {
            let mut tx = state.core.db.begin().await?;
            let updated = sqlx::query(
                r#"
                UPDATE files
                SET original_name = $1, encryption_iv = $2, wrapped_dek = $3, dek_iv = $4,
                    encryption_key_version = $5, encryption_format = $6, user_key_iv = NULL
                WHERE id = $7 AND original_name = $8
                "#,
            )
            .bind(&new_key)
            .bind(encryption_iv.to_vec())
            .bind(&wrapped_dek)
            .bind(&dek_iv)
            .bind(current)
            .bind(crypto::FORMAT_SEGMENTED_GCM)
            .bind(&row.id)
            .bind(&row.original_name)
            .execute(&mut *tx)
            .await?
            .rows_affected();

            // the plaintext behind the url is unchanged, so no cache purge
            let unused = if updated == 1 {
                &row.original_name
            } else {
                &new_key
            };
            deletion::enqueue(&mut *tx, &[Pending::object(unused.clone())]).await?;
            tx.commit().await?;

            Ok(if updated == 1 {
                Applied::Converted
            } else {
                Applied::Gone
            })
        }
    }
}

/// a fresh object key that keeps the old one's extension
fn replacement_key(old: &str) -> String {
    match old.rsplit_once('.') {
        Some((_, extension)) => format!("{}.{extension}", Uuid::new_v4()),
        None => Uuid::new_v4().to_string(),
    }
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

    const BIG: usize = 20 * 1024 * 1024;

    async fn state() -> AppState {
        dotenvy::from_path("../../../.env").ok();
        let config = Config::from_env();
        AppState {
            core: CoreState::build(&config).await,
            cloudflare: iono_core::cloudflare::CloudflareClient::new(None, None),
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
            encryption_format: crypto::FORMAT_CTR,
            has_user_key: false,
        }
    }

    /// reads the converted object back the way the viewer would
    async fn open_converted(state: &AppState, row: &PendingRow, outcome: &Outcome) -> Vec<u8> {
        let Outcome::Converted {
            new_key,
            encryption_iv,
            wrapped_dek,
            dek_iv,
        } = outcome
        else {
            panic!("expected a conversion, got a rewrap");
        };
        let dek = crypto::open_key(
            state.core.keyring.current(),
            dek_iv,
            wrapped_dek,
            &crypto::file_key_aad(&row.id),
        )
        .unwrap();
        let key = crypto::content_key(&dek, encryption_iv, None);

        let sealed = read_object(state, new_key).await;
        assert_eq!(
            sealed.len() as u64,
            crypto::sealed_len(row.size_bytes as u64)
        );
        if row.size_bytes == 0 {
            return Vec::new();
        }
        let size = row.size_bytes as u64;
        let range = crypto::sealed_range(size, 0, size - 1);
        let mut opener = crypto::Opener::new(&key, size, &range);
        let plain = opener.push(&sealed).unwrap();
        opener.finish().unwrap();
        plain
    }

    fn new_key(outcome: &Outcome) -> &str {
        match outcome {
            Outcome::Converted { new_key, .. } => new_key,
            Outcome::Rewrapped { .. } => panic!("expected a conversion"),
        }
    }

    #[test]
    fn replacement_keys_keep_the_extension() {
        assert!(replacement_key("abc.png").ends_with(".png"));
        assert_ne!(replacement_key("abc.png"), "abc.png");
        assert!(!replacement_key("abc").contains('.'));
    }

    #[test]
    fn only_files_without_a_user_key_are_rewritten() {
        let mut plain = row("k", 1, None, None);
        assert!(plain.rewritable());
        plain.encryption_iv = Some(vec![0; 16]);
        assert!(plain.rewritable(), "a ctr file without a user key");
        plain.has_user_key = true;
        assert!(!plain.rewritable(), "the user key is not ours to use");
        plain.encryption_format = crypto::FORMAT_SEGMENTED_GCM;
        plain.has_user_key = false;
        assert!(!plain.rewritable(), "format 2 is already current");
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

        let row = row(&key, plain.len(), None, None);
        let outcome = process(&state, &row).await.expect("process failed");

        assert_eq!(
            read_object(&state, &key).await,
            plain,
            "the original must stay intact until the row moves"
        );
        assert_eq!(open_converted(&state, &row, &outcome).await, plain);

        state.core.storage.delete(&key).await.unwrap();
        state.core.storage.delete(new_key(&outcome)).await.unwrap();
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

        let row = row(&key, legacy.len(), Some(legacy_iv.to_vec()), Some(version));
        let outcome = process(&state, &row).await.expect("process failed");

        assert_eq!(
            open_converted(&state, &row, &outcome).await,
            plain,
            "the legacy layer was not peeled off"
        );

        state.core.storage.delete(&key).await.unwrap();
        state.core.storage.delete(new_key(&outcome)).await.unwrap();
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

        let row = row(&key, 0, None, None);
        let outcome = process(&state, &row).await.expect("process failed");
        assert!(open_converted(&state, &row, &outcome).await.is_empty());

        state.core.storage.delete(&key).await.unwrap();
        state.core.storage.delete(new_key(&outcome)).await.unwrap();
    }
}
