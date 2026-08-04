pub mod page;
pub mod raw;
pub mod raw_with_prefix;
pub mod view_with_prefix;

use actix_web::{http::header, HttpRequest, HttpResponse};
use chrono::Utc;
use iono_core::{
    auth::password::verify_password_async,
    content_type,
    entities::{EmbedPreset, File},
    AppError,
};
use serde::Deserialize;
use sqlx::PgPool;

use iono_core::web::{append_password_query, ApiResult};

use crate::{embed, state::AppState};

#[derive(Deserialize)]
pub struct ViewQuery {
    password: Option<String>,
}

async fn view_page_inner(
    state: &AppState,
    file: File,
    raw_url_base: &str,
    query: &ViewQuery,
) -> ApiResult<HttpResponse> {
    if !unlock(&file, query.password.as_deref()).await? {
        return Err(AppError::NotFound.into());
    }

    let raw_url = append_password_query(raw_url_base, query.password.as_deref());
    let active = fetch_active_preset(&state.db, &file.user_id).await?;
    let (preset, uploader) = match active {
        Some(active) => (Some(active.preset), active.username),
        None => (None, String::new()),
    };
    let html = embed::render_embed_html(&file, &uploader, &raw_url, preset.as_ref());

    Ok(HttpResponse::Ok()
        .content_type(header::ContentType::html())
        .body(html))
}

async fn raw_file_inner(
    state: &AppState,
    file: File,
    query: &ViewQuery,
    req: &HttpRequest,
) -> ApiResult<HttpResponse> {
    if !unlock(&file, query.password.as_deref()).await? {
        return Err(AppError::NotFound.into());
    }

    let range = req
        .headers()
        .get(header::RANGE)
        .and_then(|v| v.to_str().ok());
    let object = state.storage.get(&file.original_name, range).await?;

    let disposition = header::ContentDisposition {
        disposition: if content_type::is_inline_safe(&file.content_type) {
            header::DispositionType::Inline
        } else {
            header::DispositionType::Attachment
        },
        parameters: vec![header::DispositionParam::Filename(
            file.display_name.clone(),
        )],
    };

    let mut builder = if object.content_range.is_some() {
        HttpResponse::PartialContent()
    } else {
        HttpResponse::Ok()
    };
    builder
        .content_type(file.content_type.clone())
        .append_header((header::X_CONTENT_TYPE_OPTIONS, "nosniff"))
        .append_header((header::ACCEPT_RANGES, "bytes"))
        .append_header(cache_control(&file))
        .append_header(disposition);
    if let Some(content_range) = &object.content_range {
        builder.append_header((header::CONTENT_RANGE, content_range.clone()));
    }
    if let Some(len) = object.content_length {
        builder.no_chunking(len);
    }

    Ok(builder.streaming(object.stream))
}

fn cache_control(file: &File) -> header::CacheControl {
    // browsers use max-age which must be short so mutations propagate quickly
    // cloudflare uses s-maxage which can be long since we can purge it on mutation
    const BROWSER_MAX_AGE: u32 = 300;
    const EDGE_MAX_AGE: u32 = 31_536_000;
    if file.password_hash.is_some() {
        return header::CacheControl(vec![header::CacheDirective::NoStore]);
    }
    let cap = file
        .expires_at
        .map(|expires| {
            (expires - Utc::now())
                .num_seconds()
                .clamp(0, EDGE_MAX_AGE as i64) as u32
        })
        .unwrap_or(EDGE_MAX_AGE);
    header::CacheControl(vec![
        header::CacheDirective::Public,
        header::CacheDirective::MaxAge(BROWSER_MAX_AGE.min(cap)),
        header::CacheDirective::SMaxAge(cap),
    ])
}

async fn fetch_file(state: &AppState, display_name: &str) -> Result<File, AppError> {
    sqlx::query_as::<_, File>(
        r#"
        SELECT f.* FROM files f
        INNER JOIN users u ON u.id = f.user_id
        WHERE f.display_name = $1
          AND (f.expires_at IS NULL OR f.expires_at > now())
          AND u.deleted_at IS NULL
        "#,
    )
    .bind(display_name)
    .fetch_optional(&state.db)
    .await
    .map_err(AppError::from)?
    .ok_or(AppError::NotFound)
}

async fn fetch_file_with_prefix(
    state: &AppState,
    prefix: &str,
    display_name: &str,
) -> Result<File, AppError> {
    sqlx::query_as::<_, File>(
        r#"
        SELECT f.* FROM files f
        INNER JOIN domain_settings ds ON ds.user_id = f.user_id
        INNER JOIN users u ON u.id = f.user_id
        WHERE f.display_name = $1
          AND ds.files_path_prefix = $2
          AND (f.expires_at IS NULL OR f.expires_at > now())
          AND u.deleted_at IS NULL
        "#,
    )
    .bind(display_name)
    .bind(prefix)
    .fetch_optional(&state.db)
    .await
    .map_err(AppError::from)?
    .ok_or(AppError::NotFound)
}

#[derive(sqlx::FromRow)]
struct ActivePreset {
    #[sqlx(flatten)]
    preset: EmbedPreset,
    username: String,
}

async fn fetch_active_preset(db: &PgPool, user_id: &str) -> Result<Option<ActivePreset>, AppError> {
    sqlx::query_as::<_, ActivePreset>(
        r#"
        SELECT p.*, u.username FROM embed_settings s
        INNER JOIN embed_presets p ON p.id = s.active_preset_id
        INNER JOIN users u ON u.id = s.user_id
        WHERE s.user_id = $1 AND s.enabled
        "#,
    )
    .bind(user_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::from)
}

async fn unlock(file: &File, provided: Option<&str>) -> Result<bool, AppError> {
    let Some(hash) = file.password_hash.clone() else {
        return Ok(true);
    };
    let Some(provided) = provided.map(str::to_owned) else {
        return Ok(false);
    };

    verify_password_async(provided, hash).await
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn seed_preset(db: &PgPool, enabled: bool) {
        sqlx::query(
            "INSERT INTO users (id, username, email) VALUES ('u1', 'cat', 'cat@iono.test')",
        )
        .execute(db)
        .await
        .unwrap();
        sqlx::query(
            r#"
            INSERT INTO embed_presets (id, user_id, name, title, description, color)
            VALUES ('p1', 'u1', 'default', '{filename}', 'by {uploader}', '#7c3aed')
            "#,
        )
        .execute(db)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO embed_settings (user_id, enabled, active_preset_id) VALUES ('u1', $1, 'p1')",
        )
        .bind(enabled)
        .execute(db)
        .await
        .unwrap();
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn active_preset_maps_both_tables(db: PgPool) {
        seed_preset(&db, true).await;

        let active = fetch_active_preset(&db, "u1")
            .await
            .unwrap()
            .expect("preset should be active");

        assert_eq!(active.username, "cat");
        assert_eq!(active.preset.id, "p1");
        assert_eq!(active.preset.user_id, "u1");
        assert_eq!(active.preset.name, "default");
        assert_eq!(active.preset.title.as_deref(), Some("{filename}"));
        assert_eq!(active.preset.description.as_deref(), Some("by {uploader}"));
        assert_eq!(active.preset.color.as_deref(), Some("#7c3aed"));
        assert_eq!(active.preset.site_name, None);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn no_preset_when_embeds_disabled(db: PgPool) {
        seed_preset(&db, false).await;

        assert!(fetch_active_preset(&db, "u1").await.unwrap().is_none());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn no_preset_for_unknown_user(db: PgPool) {
        assert!(fetch_active_preset(&db, "nobody").await.unwrap().is_none());
    }
}
