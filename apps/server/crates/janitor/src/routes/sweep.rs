use actix_web::{post, web, HttpResponse};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use iono_core::{deletion::Deleter, AppError};
use secrecy::ExposeSecret;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use subtle::ConstantTimeEq;

use crate::state::AppState;

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

async fn run_sweep(state: &AppState) -> Result<(u64, u64), AppError> {
    let mut deleted: u64 = 0;
    let mut failed: u64 = 0;
    // expired rows hand their objects to the outbox in the same statement.
    // their cached copies need no purge, the cache lifetime never outlives
    // expires_at
    loop {
        let queued = sqlx::query(
            r#"
            WITH gone AS (
                DELETE FROM files
                WHERE id IN (
                    SELECT id FROM files
                    WHERE expires_at IS NOT NULL AND expires_at < now()
                    LIMIT $1
                )
                RETURNING original_name
            )
            INSERT INTO pending_deletions (id, s3_key)
            SELECT gen_random_uuid()::text, original_name FROM gone
            "#,
        )
        .bind(state.core.config.sweep_batch_size)
        .execute(&state.core.db)
        .await?
        .rows_affected();

        if queued == 0 {
            break;
        }
        deleted += queued;
    }

    let (aborted_uploads, abort_failed) = abort_expired_upload_sessions(state).await?;
    deleted += aborted_uploads;
    failed += abort_failed;

    let expired_pastes =
        sqlx::query("DELETE FROM pastes WHERE expires_at IS NOT NULL AND expires_at < now()")
            .execute(&state.core.db)
            .await?
            .rows_affected();
    deleted += expired_pastes;

    let expired_links =
        sqlx::query("DELETE FROM short_links WHERE expires_at IS NOT NULL AND expires_at < now()")
            .execute(&state.core.db)
            .await?
            .rows_affected();
    deleted += expired_links;

    // only left behind when an upload died mid stream
    deleted += sqlx::query("DELETE FROM storage_reservations WHERE expires_at < now()")
        .execute(&state.core.db)
        .await?
        .rows_affected();

    let expired_oauth_flows = sqlx::query("DELETE FROM oauth_flow_states WHERE expires_at < now()")
        .execute(&state.core.db)
        .await?
        .rows_affected();
    deleted += expired_oauth_flows;

    let dead_refresh_tokens =
        sqlx::query("DELETE FROM refresh_tokens WHERE expires_at < now() OR revoked_at < now() - interval '7 days'")
            .execute(&state.core.db)
            .await?
            .rows_affected();
    deleted += dead_refresh_tokens;

    let reverted_plans = sqlx::query(
        r#"
        UPDATE users SET plan_id = 'free', plan_expires_at = NULL
        WHERE plan_expires_at IS NOT NULL AND plan_expires_at <= now()
        "#,
    )
    .execute(&state.core.db)
    .await?
    .rows_affected();
    deleted += reverted_plans;

    deleted += purge_expired_deletions(state).await?;

    // last, so it also picks up everything the steps above queued
    let deleter = Deleter {
        db: &state.core.db,
        storage: state.core.storage.as_ref(),
        cloudflare: &state.cloudflare,
    };
    while deleter
        .process_backlog(state.core.config.sweep_batch_size)
        .await?
        .done
        > 0
    {}
    let backlog: i64 = sqlx::query_scalar("SELECT count(*) FROM pending_deletions")
        .fetch_one(&state.core.db)
        .await?;
    failed += backlog as u64;

    Ok((deleted, failed))
}

// abandoned chunked uploads, whose stored parts r2 would otherwise keep
async fn abort_expired_upload_sessions(state: &AppState) -> Result<(u64, u64), AppError> {
    let expired: Vec<(String, String, String)> = sqlx::query_as(
        r#"
        SELECT id, s3_key, s3_upload_id FROM upload_sessions
        WHERE expires_at < now()
        LIMIT $1
        "#,
    )
    .bind(state.core.config.sweep_batch_size)
    .fetch_all(&state.core.db)
    .await?;

    let mut aborted: u64 = 0;
    let mut failed: u64 = 0;
    for (id, s3_key, upload_id) in expired {
        if let Err(e) = state
            .core
            .storage
            .abort_multipart(&s3_key, &upload_id)
            .await
        {
            tracing::warn!(s3_key = %s3_key, error = %e, "could not abort expired multipart upload");
            failed += 1;
            continue;
        }
        sqlx::query("DELETE FROM upload_sessions WHERE id = $1")
            .bind(&id)
            .execute(&state.core.db)
            .await?;
        aborted += 1;
    }

    Ok((aborted, failed))
}

async fn purge_expired_deletions(state: &AppState) -> Result<u64, AppError> {
    let expired_user_ids: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT id FROM users
        WHERE deleted_at IS NOT NULL
          AND deleted_at < now() - make_interval(days => $1)
          AND (email IS NOT NULL OR password_hash IS NOT NULL)
        LIMIT $2
        "#,
    )
    .bind(state.core.config.recovery_window_days as i32)
    .bind(state.core.config.sweep_batch_size)
    .fetch_all(&state.core.db)
    .await?;

    let mut purged: u64 = 0;

    for user_id in expired_user_ids {
        let mut tx = state.core.db.begin().await?;

        // their content was purged from the edge when the account was deleted
        sqlx::query(
            r#"
            INSERT INTO pending_deletions (id, s3_key)
            SELECT gen_random_uuid()::text, original_name FROM files WHERE user_id = $1
            "#,
        )
        .bind(&user_id)
        .execute(&mut *tx)
        .await?;

        for query in [
            "DELETE FROM files WHERE user_id = $1",
            "DELETE FROM folders WHERE user_id = $1",
            "DELETE FROM pastes WHERE user_id = $1",
            "DELETE FROM short_links WHERE user_id = $1",
            "DELETE FROM api_keys WHERE user_id = $1",
            "DELETE FROM refresh_tokens WHERE user_id = $1",
            "DELETE FROM passkeys WHERE user_id = $1",
            "DELETE FROM embed_presets WHERE user_id = $1",
            "DELETE FROM embed_settings WHERE user_id = $1",
            "DELETE FROM domain_settings WHERE user_id = $1",
            "DELETE FROM user_settings WHERE user_id = $1",
            "DELETE FROM totp_recovery_codes WHERE user_id = $1",
            "DELETE FROM oauth_accounts WHERE user_id = $1",
            "DELETE FROM subscriptions WHERE user_id = $1",
        ] {
            sqlx::query(query).bind(&user_id).execute(&mut *tx).await?;
        }

        sqlx::query(
            r#"
            UPDATE users SET
                email         = NULL,
                password_hash = NULL,
                totp_secret   = NULL,
                totp_enabled  = false,
                token_version = token_version + 1
            WHERE id = $1
            "#,
        )
        .bind(&user_id)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        purged += 1;
    }

    Ok(purged)
}
