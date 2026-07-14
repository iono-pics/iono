use actix_web::{get, http::header, web, HttpRequest, HttpResponse};
use chrono::Utc;
use iono_core::{
    auth::password,
    content_type,
    entities::{EmbedPreset, File},
    AppError,
};
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde::Deserialize;

use crate::{embed, error::ApiResult, state::AppState};

#[derive(Deserialize)]
pub struct ViewQuery {
    password: Option<String>,
}

#[get("/{display_name}")]
pub async fn view_page(
    state: web::Data<AppState>,
    path: web::Path<String>,
    query: web::Query<ViewQuery>,
) -> ApiResult<HttpResponse> {
    let display_name = path.into_inner();
    let file = fetch_file(&state, &display_name).await?;
    view_page_inner(&state, file, &format!("/raw/{display_name}"), &query).await
}

#[get("/raw/{display_name}")]
pub async fn raw_file(
    state: web::Data<AppState>,
    path: web::Path<String>,
    query: web::Query<ViewQuery>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    let display_name = path.into_inner();
    let file = fetch_file(&state, &display_name).await?;
    raw_file_inner(&state, file, &query, &req).await
}

#[get("/{prefix}/{display_name}")]
pub async fn view_page_with_prefix(
    state: web::Data<AppState>,
    path: web::Path<(String, String)>,
    query: web::Query<ViewQuery>,
) -> ApiResult<HttpResponse> {
    let (prefix, display_name) = path.into_inner();
    let file = fetch_file_with_prefix(&state, &prefix, &display_name).await?;
    view_page_inner(
        &state,
        file,
        &format!("/{prefix}/raw/{display_name}"),
        &query,
    )
    .await
}

#[get("/{prefix}/raw/{display_name}")]
pub async fn raw_file_with_prefix(
    state: web::Data<AppState>,
    path: web::Path<(String, String)>,
    query: web::Query<ViewQuery>,
    req: HttpRequest,
) -> ApiResult<HttpResponse> {
    let (prefix, display_name) = path.into_inner();
    let file = fetch_file_with_prefix(&state, &prefix, &display_name).await?;
    raw_file_inner(&state, file, &query, &req).await
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

    let raw_url = raw_url_for(raw_url_base, query.password.as_deref());
    let preset = fetch_active_preset(state, &file.user_id).await?;
    let html = embed::render_embed_html(&file, &raw_url, preset.as_ref());

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
    const YEAR: u32 = 31_536_000;
    if file.password_hash.is_some() {
        return header::CacheControl(vec![header::CacheDirective::NoStore]);
    }
    let max_age = file
        .expires_at
        .map(|expires| (expires - Utc::now()).num_seconds().clamp(0, YEAR as i64) as u32)
        .unwrap_or(YEAR);
    header::CacheControl(vec![
        header::CacheDirective::Public,
        header::CacheDirective::MaxAge(max_age),
        header::CacheDirective::Extension("immutable".to_owned(), None),
    ])
}

async fn fetch_file(state: &AppState, display_name: &str) -> Result<File, AppError> {
    sqlx::query_as::<_, File>(
        "SELECT * FROM files WHERE display_name = $1 AND (expires_at IS NULL OR expires_at > now())",
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
        WHERE f.display_name = $1
        AND ds.files_path_prefix = $2
        AND (f.expires_at IS NULL OR f.expires_at > now())
        "#,
    )
    .bind(display_name)
    .bind(prefix)
    .fetch_optional(&state.db)
    .await
    .map_err(AppError::from)?
    .ok_or(AppError::NotFound)
}

async fn fetch_active_preset(
    state: &AppState,
    user_id: &str,
) -> Result<Option<EmbedPreset>, AppError> {
    sqlx::query_as::<_, EmbedPreset>(
        r#"
        SELECT p.* FROM embed_settings s
        INNER JOIN embed_presets p ON p.id = s.active_preset_id
        WHERE s.user_id = $1 AND s.enabled
        "#,
    )
    .bind(user_id)
    .fetch_optional(&state.db)
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

    tokio::task::spawn_blocking(move || password::verify_password(&provided, &hash))
        .await
        .map_err(|e| AppError::internal_from("password verification task panicked", e))?
}

fn raw_url_for(base: &str, password: Option<&str>) -> String {
    match password {
        Some(p) => format!(
            "{base}?password={}",
            utf8_percent_encode(p, NON_ALPHANUMERIC)
        ),
        None => base.to_string(),
    }
}
