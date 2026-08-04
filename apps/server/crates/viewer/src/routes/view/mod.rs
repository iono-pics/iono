pub mod page;
pub mod raw;
pub mod raw_with_prefix;
pub mod view_with_prefix;

use actix_web::{http::header, HttpRequest, HttpResponse};
use bytes::Bytes;
use futures_util::stream::{BoxStream, StreamExt};
use iono_core::{
    auth::password::verify_password_async,
    content_type, crypto,
    entities::{EmbedPreset, File},
    AppError,
};
use serde::Deserialize;
use sqlx::PgPool;

use iono_core::web::{append_query, ApiResult};

use crate::{cache, csp, embed, state::AppState};

#[derive(Deserialize)]
pub struct ViewQuery {
    password: Option<String>,
    key: Option<String>,
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
    verify_user_key(&file, query.key.as_deref()).await?;

    let raw_url = append_query(
        raw_url_base,
        &[
            ("password", query.password.as_deref()),
            ("key", query.key.as_deref()),
        ],
    );
    let active = fetch_active_preset(&state.db, &file.user_id).await?;
    let (preset, uploader) = match active {
        Some(active) => (Some(active.preset), active.username),
        None => (None, String::new()),
    };
    let nonce = csp::Nonce::new();
    let html = embed::render_embed_html(&file, &uploader, &raw_url, preset.as_ref(), &nonce);

    Ok(HttpResponse::Ok()
        .content_type(header::ContentType::html())
        .append_header((header::X_CONTENT_TYPE_OPTIONS, "nosniff"))
        .append_header(csp::header(&csp::view_policy(&nonce)))
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

    let user_key = verify_user_key(&file, query.key.as_deref()).await?;

    let range = req
        .headers()
        .get(header::RANGE)
        .and_then(|v| v.to_str().ok());
    let object = state.storage.get(&file.original_name, range).await?;

    let offset = object
        .content_range
        .as_deref()
        .and_then(range_start)
        .unwrap_or(0);
    let layers = decryption_layers(state, &file, user_key.as_deref(), offset)?;
    let stream = decrypting_stream(object.stream, layers);

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
        .append_header(csp::header(csp::raw_policy()))
        .append_header((header::ACCEPT_RANGES, "bytes"))
        .append_header(cache_control(
            cache::MaxAges::from_config(&state.config),
            &file,
        ))
        .append_header(disposition);
    if let Some(content_range) = &object.content_range {
        builder.append_header((header::CONTENT_RANGE, content_range.clone()));
    }
    if let Some(len) = object.content_length {
        builder.no_chunking(len);
    }

    Ok(builder.streaming(stream))
}

fn range_start(content_range: &str) -> Option<u64> {
    content_range
        .strip_prefix("bytes ")?
        .split('-')
        .next()?
        .trim()
        .parse()
        .ok()
}

async fn verify_user_key(file: &File, provided: Option<&str>) -> Result<Option<String>, AppError> {
    let Some(hash) = file.user_key_hash.clone() else {
        return Ok(None);
    };
    let Some(provided) = provided.map(str::to_owned) else {
        return Err(AppError::NotFound);
    };
    if !verify_password_async(provided.clone(), hash).await? {
        return Err(AppError::NotFound);
    }
    Ok(Some(provided))
}

fn decryption_layers(
    state: &AppState,
    file: &File,
    user_key: Option<&str>,
    offset: u64,
) -> Result<crypto::Layers, AppError> {
    let mut layers = Vec::new();

    if let Some(iv) = file.encryption_iv.as_deref() {
        let kek = state
            .keyring
            .get(file.encryption_key_version.unwrap_or(1))?;

        let key = match (file.wrapped_dek.as_deref(), file.dek_iv.as_deref()) {
            (Some(wrapped), Some(dek_iv)) => crypto::unwrap_key(kek, &iv_array(dek_iv)?, wrapped)?,
            _ => *kek,
        };

        layers.push(crypto::Keystream::at(&key, &iv_array(iv)?, offset)?);
    }

    if let (Some(key), Some(iv)) = (user_key, file.user_key_iv.as_deref()) {
        let key = crypto::parse_key(key)?;
        layers.push(crypto::Keystream::at(&key, &iv_array(iv)?, offset)?);
    }

    Ok(crypto::Layers::new(layers))
}

fn iv_array(iv: &[u8]) -> Result<[u8; crypto::IV_LEN], AppError> {
    iv.try_into()
        .map_err(|_| AppError::internal("stored encryption iv is malformed"))
}

fn decrypting_stream(
    stream: BoxStream<'static, std::io::Result<Bytes>>,
    mut layers: crypto::Layers,
) -> BoxStream<'static, std::io::Result<Bytes>> {
    if layers.is_empty() {
        return stream;
    }
    Box::pin(stream.map(move |chunk| {
        chunk.map(|bytes| {
            let mut buf = bytes.to_vec();
            layers.apply(&mut buf);
            Bytes::from(buf)
        })
    }))
}

fn cache_control(ages: cache::MaxAges, file: &File) -> header::CacheControl {
    let secret = file.password_hash.is_some() || file.user_key_hash.is_some();
    cache::cache_control(ages, file.expires_at, secret)
}

async fn fetch_file(state: &AppState, display_name: &str) -> Result<File, AppError> {
    sqlx::query_as::<_, File>(
        r#"
        SELECT f.* FROM files f
        INNER JOIN users u ON u.id = f.user_id
        LEFT JOIN domain_settings ds ON ds.user_id = f.user_id
        WHERE f.display_name = $1
          AND ds.files_path_prefix IS NULL
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
            "UPDATE embed_settings SET enabled = $1, active_preset_id = 'p1' WHERE user_id = 'u1'",
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
