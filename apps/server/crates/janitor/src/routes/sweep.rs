use actix_web::{post, web, HttpResponse};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use iono_core::AppError;
use secrecy::ExposeSecret;
use std::collections::HashSet;
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
    loop {
        let batch: Vec<(String, String)> = sqlx::query_as(
            r#"
            SELECT id, original_name FROM files
            WHERE expires_at IS NOT NULL AND expires_at < now()
            LIMIT $1
            "#,
        )
        .bind(state.core.config.sweep_batch_size)
        .fetch_all(&state.core.db)
        .await?;

        if batch.is_empty() {
            break;
        }

        let keys: Vec<String> = batch.iter().map(|(_, key)| key.clone()).collect();
        let deleted_keys: HashSet<String> = state
            .core
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
            .execute(&state.core.db)
            .await?;

        deleted += deleted_ids.len() as u64;
    }

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

    let (purged_users, purged_files_failed) = purge_expired_deletions(state).await?;
    deleted += purged_users;
    failed += purged_files_failed;

    Ok((deleted, failed))
}

async fn purge_expired_deletions(state: &AppState) -> Result<(u64, u64), AppError> {
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
    let mut failed: u64 = 0;

    for user_id in expired_user_ids {
        let s3_keys: Vec<String> =
            sqlx::query_scalar("SELECT original_name FROM files WHERE user_id = $1")
                .bind(&user_id)
                .fetch_all(&state.core.db)
                .await?;

        let mut tx = state.core.db.begin().await?;
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

        if !s3_keys.is_empty() {
            let deleted_keys: HashSet<String> = state
                .core
                .storage
                .delete_many(&s3_keys)
                .await?
                .into_iter()
                .collect();
            failed += (s3_keys.len() - deleted_keys.len()) as u64;
        }
        purged += 1;
    }

    Ok((purged, failed))
}
