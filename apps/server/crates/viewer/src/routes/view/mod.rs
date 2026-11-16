pub mod page;
pub mod raw;
pub mod raw_with_prefix;
pub mod view_with_prefix;

use actix_web::{http::header, HttpRequest, HttpResponse};
use bytes::Bytes;
use futures_util::stream::{BoxStream, StreamExt};
use iono_core::{
    auth::password::{hash_secret, is_legacy_secret_hash, verify_password_async, verify_secret},
    content_type, crypto,
    entities::{EmbedPreset, File},
    rate_limit::request_ip,
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
    req: &HttpRequest,
    file: File,
    raw_url_base: &str,
    query: &ViewQuery,
) -> ApiResult<HttpResponse> {
    if !unlock(state, req, &file, query.password.as_deref()).await? {
        return Err(AppError::NotFound.into());
    }
    verify_user_key(state, req, &file, query.key.as_deref()).await?;

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
    if !unlock(state, req, &file, query.password.as_deref()).await? {
        return Err(AppError::NotFound.into());
    }

    let user_key = verify_user_key(state, req, &file, query.key.as_deref()).await?;

    let range = req
        .headers()
        .get(header::RANGE)
        .and_then(|v| v.to_str().ok());
    let body = if file.encryption_format == crypto::FORMAT_SEGMENTED_GCM {
        sealed_body(state, &file, user_key.as_deref(), range).await?
    } else {
        legacy_body(state, &file, user_key.as_deref(), range).await?
    };

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

    let mut builder = if body.content_range.is_some() {
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
        .append_header(cache::file_tags(&file.id, &file.user_id))
        .append_header(disposition);
    if let Some(content_range) = &body.content_range {
        builder.append_header((header::CONTENT_RANGE, content_range.clone()));
    }
    if let Some(len) = body.content_length {
        builder.no_chunking(len);
    }

    Ok(builder.streaming(body.stream))
}

struct Body {
    stream: BoxStream<'static, std::io::Result<Bytes>>,
    content_range: Option<String>,
    content_length: Option<u64>,
}

/// format 2. the client's plaintext range is widened to whole segments for
/// storage, then opened and trimmed back down
async fn sealed_body(
    state: &AppState,
    file: &File,
    user_key: Option<&str>,
    range: Option<&str>,
) -> Result<Body, AppError> {
    let size = file.size_bytes as u64;
    let wanted = match range.map(|r| parse_range(r, size)) {
        None | Some(RangeRequest::Whole) => None,
        Some(RangeRequest::Unsatisfiable) => return Err(AppError::RangeNotSatisfiable),
        Some(RangeRequest::Bytes(start, end)) => Some((start, end)),
    };
    if size == 0 {
        return Ok(Body {
            stream: Box::pin(futures_util::stream::empty()),
            content_range: None,
            content_length: Some(0),
        });
    }

    let key = sealed_content_key(state, file, user_key)?;
    let (start, end) = wanted.unwrap_or((0, size - 1));
    let sealed = crypto::sealed_range(size, start, end)?;
    let object = state
        .storage
        .get(
            &file.original_name,
            Some(&format!(
                "bytes={}-{}",
                sealed.sealed_start, sealed.sealed_end_inclusive
            )),
        )
        .await?;

    Ok(Body {
        stream: opening_stream(object.stream, crypto::Opener::new(&key, size, &sealed)),
        content_range: wanted.map(|_| format!("bytes {start}-{end}/{size}")),
        content_length: Some(end - start + 1),
    })
}

fn sealed_content_key(
    state: &AppState,
    file: &File,
    user_key: Option<&str>,
) -> Result<[u8; crypto::KEY_LEN], AppError> {
    let (Some(wrapped), Some(nonce), Some(salt), Some(version)) = (
        file.wrapped_dek.as_deref(),
        file.dek_iv.as_deref(),
        file.encryption_iv.as_deref(),
        file.encryption_key_version,
    ) else {
        return Err(AppError::internal("format 2 file has no key envelope"));
    };
    let dek = crypto::open_key(
        state.keyring.get(version)?,
        nonce,
        wrapped,
        &crypto::file_key_aad(&file.id),
    )?;
    let user_key = user_key.map(crypto::parse_key).transpose()?;
    Ok(crypto::content_key(&dek, salt, user_key.as_ref()))
}

// a segment that fails authentication ends the response with an error, so
// unverified bytes are never sent
fn opening_stream(
    inner: BoxStream<'static, std::io::Result<Bytes>>,
    opener: crypto::Opener,
) -> BoxStream<'static, std::io::Result<Bytes>> {
    Box::pin(futures_util::stream::unfold(
        Some((inner, opener)),
        |state| async move {
            let (mut inner, mut opener) = state?;
            loop {
                match inner.next().await {
                    Some(Ok(bytes)) => match opener.push(&bytes) {
                        Ok(plain) if plain.is_empty() => continue,
                        Ok(plain) => return Some((Ok(Bytes::from(plain)), Some((inner, opener)))),
                        Err(e) => return Some((Err(std::io::Error::other(e)), None)),
                    },
                    Some(Err(e)) => return Some((Err(e), None)),
                    None => {
                        return opener
                            .finish()
                            .err()
                            .map(|e| (Err(std::io::Error::other(e)), None))
                    }
                }
            }
        },
    ))
}

#[derive(Debug, PartialEq, Eq)]
enum RangeRequest {
    Whole,
    Bytes(u64, u64),
    Unsatisfiable,
}

/// one byte range, as media players send. anything else, like several ranges
/// at once, is answered with the whole file as rfc 9110 allows
fn parse_range(header: &str, size: u64) -> RangeRequest {
    let Some(spec) = header.trim().strip_prefix("bytes=") else {
        return RangeRequest::Whole;
    };
    if spec.contains(',') {
        return RangeRequest::Whole;
    }
    let Some((first, last)) = spec.trim().split_once('-') else {
        return RangeRequest::Whole;
    };
    let (first, last) = (first.trim(), last.trim());

    if first.is_empty() {
        return match last.parse::<u64>() {
            Ok(0) => RangeRequest::Unsatisfiable,
            Ok(_) if size == 0 => RangeRequest::Unsatisfiable,
            Ok(suffix) => RangeRequest::Bytes(size.saturating_sub(suffix), size - 1),
            Err(_) => RangeRequest::Whole,
        };
    }

    let Ok(start) = first.parse::<u64>() else {
        return RangeRequest::Whole;
    };
    let end = if last.is_empty() {
        u64::MAX
    } else {
        match last.parse::<u64>() {
            Ok(end) if end >= start => end,
            _ => return RangeRequest::Whole,
        }
    };
    if start >= size {
        return RangeRequest::Unsatisfiable;
    }
    RangeRequest::Bytes(start, end.min(size - 1))
}

/// format 1 and unencrypted files. ctr maps bytes one to one, so storage can
/// serve the client's range as is
async fn legacy_body(
    state: &AppState,
    file: &File,
    user_key: Option<&str>,
    range: Option<&str>,
) -> Result<Body, AppError> {
    let object = state.storage.get(&file.original_name, range).await?;
    let offset = object
        .content_range
        .as_deref()
        .and_then(range_start)
        .unwrap_or(0);
    let layers = decryption_layers(state, file, user_key, offset)?;
    Ok(Body {
        stream: decrypting_stream(object.stream, layers),
        content_range: object.content_range,
        content_length: object.content_length,
    })
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

async fn verify_user_key(
    state: &AppState,
    req: &HttpRequest,
    file: &File,
    provided: Option<&str>,
) -> Result<Option<String>, AppError> {
    let Some(stored) = file.user_key_hash.as_deref() else {
        return Ok(None);
    };
    let Some(provided) = provided else {
        return Err(AppError::NotFound);
    };

    // only argon2 hashes need the slow check
    let matched = if is_legacy_secret_hash(stored) {
        let matched = state
            .unlocker
            .check(request_ip(req), &file.id, stored, provided, || async {
                Ok(verify_secret(provided, stored).await?.matched())
            })
            .await?;
        if matched {
            upgrade_user_key_hash(state, &file.id, stored, provided).await;
        }
        matched
    } else {
        verify_secret(provided, stored).await?.matched()
    };

    if !matched {
        return Err(AppError::NotFound);
    }
    Ok(Some(provided.to_owned()))
}

async fn upgrade_user_key_hash(state: &AppState, file_id: &str, legacy: &str, key: &str) {
    let result =
        sqlx::query("UPDATE files SET user_key_hash = $1 WHERE id = $2 AND user_key_hash = $3")
            .bind(hash_secret(key))
            .bind(file_id)
            .bind(legacy)
            .execute(&state.db)
            .await;
    if let Err(e) = result {
        tracing::warn!(file_id = %file_id, error = %e, "could not upgrade user key hash");
    }
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
            (Some(wrapped), Some(dek_iv)) => {
                crypto::open_key(kek, dek_iv, wrapped, &crypto::file_key_aad(&file.id))?
            }
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

async fn unlock(
    state: &AppState,
    req: &HttpRequest,
    file: &File,
    provided: Option<&str>,
) -> Result<bool, AppError> {
    let Some(stored) = file.password_hash.as_deref() else {
        return Ok(true);
    };
    let Some(provided) = provided else {
        return Ok(false);
    };

    state
        .unlocker
        .check(request_ip(req), &file.id, stored, provided, || {
            verify_password_async(provided.to_owned(), stored.to_owned())
        })
        .await
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

    #[test]
    fn ranges_cover_what_media_players_send() {
        assert_eq!(parse_range("bytes=0-99", 1000), RangeRequest::Bytes(0, 99));
        assert_eq!(
            parse_range("bytes=500-", 1000),
            RangeRequest::Bytes(500, 999)
        );
        assert_eq!(
            parse_range("bytes=-100", 1000),
            RangeRequest::Bytes(900, 999)
        );
        assert_eq!(
            parse_range("bytes=-5000", 1000),
            RangeRequest::Bytes(0, 999)
        );
        assert_eq!(
            parse_range("bytes=900-5000", 1000),
            RangeRequest::Bytes(900, 999)
        );
    }

    #[test]
    fn ranges_past_the_end_are_unsatisfiable() {
        assert_eq!(
            parse_range("bytes=1000-", 1000),
            RangeRequest::Unsatisfiable
        );
        assert_eq!(parse_range("bytes=-0", 1000), RangeRequest::Unsatisfiable);
        assert_eq!(parse_range("bytes=0-", 0), RangeRequest::Unsatisfiable);
    }

    #[test]
    fn ranges_we_do_not_handle_get_the_whole_file() {
        assert_eq!(parse_range("bytes=0-1,5-6", 1000), RangeRequest::Whole);
        assert_eq!(parse_range("items=0-1", 1000), RangeRequest::Whole);
        assert_eq!(parse_range("bytes=9-3", 1000), RangeRequest::Whole);
        assert_eq!(parse_range("bytes=x-3", 1000), RangeRequest::Whole);
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
