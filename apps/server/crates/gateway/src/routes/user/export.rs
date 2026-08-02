use actix_web::{get, http::header, web, HttpResponse};
use chrono::{DateTime, Utc};
use iono_core::{urls, web::ApiResult, AppError};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{auth::JwtUser, state::AppState};

#[derive(Debug, Deserialize, Default, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ExportType {
    Files,
    Pastes,
    Links,
    #[default]
    All,
}

#[derive(Debug, Deserialize)]
pub struct ExportQuery {
    #[serde(default, rename = "type")]
    kind: ExportType,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
struct FileExport {
    id: String,
    display_name: String,
    #[sqlx(skip)]
    url: Option<String>,
    #[sqlx(skip)]
    raw_url: Option<String>,
    content_type: String,
    size_bytes: i64,
    folder_id: Option<String>,
    is_favourite: bool,
    password_protected: bool,
    expires_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
struct PasteExport {
    id: String,
    key: String,
    #[sqlx(skip)]
    url: Option<String>,
    title: Option<String>,
    content: String,
    syntax: Option<String>,
    password_protected: bool,
    expires_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
struct LinkExport {
    id: String,
    key: String,
    #[sqlx(skip)]
    url: Option<String>,
    target_url: String,
    expires_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
struct FolderExport {
    id: String,
    name: String,
    parent_id: Option<String>,
    created_at: DateTime<Utc>,
}

#[utoipa::path(
    get,
    path = "/user/export",
    security(("bearer_auth" = [])),
    params(
        ("type" = Option<ExportType>, Query, description = "which resource types to export"),
    ),
    responses(
        (status = 200, description = "JSON dump attached as a download"),
        (status = 401, description = "missing or invalid token"),
    )
)]
#[get("/export")]
pub async fn export_data(
    state: web::Data<AppState>,
    user: JwtUser,
    query: web::Query<ExportQuery>,
) -> ApiResult<HttpResponse> {
    let kind = query.into_inner().kind;
    let user_id = &user.0.id;

    let mut body = serde_json::Map::new();
    body.insert("user_id".into(), serde_json::json!(user_id));
    body.insert("exported_at".into(), serde_json::json!(Utc::now()));

    if matches!(kind, ExportType::Files | ExportType::All) {
        body.insert(
            "files".into(),
            serde_json::json!(fetch_files(&state, user_id).await?),
        );
    }
    if matches!(kind, ExportType::Pastes | ExportType::All) {
        body.insert(
            "pastes".into(),
            serde_json::json!(fetch_pastes(&state, user_id).await?),
        );
    }
    if matches!(kind, ExportType::Links | ExportType::All) {
        body.insert(
            "links".into(),
            serde_json::json!(fetch_links(&state, user_id).await?),
        );
    }
    if matches!(kind, ExportType::All) {
        body.insert(
            "folders".into(),
            serde_json::json!(fetch_folders(&state, user_id).await?),
        );
    }

    let filename = format!("iono-export-{}.json", Utc::now().format("%Y%m%d"));

    Ok(HttpResponse::Ok()
        .content_type(header::ContentType::json())
        .insert_header((
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{filename}\""),
        ))
        .insert_header((header::CACHE_CONTROL, "no-store"))
        .json(body))
}

async fn fetch_files(state: &AppState, user_id: &str) -> Result<Vec<FileExport>, AppError> {
    let mut files: Vec<FileExport> = sqlx::query_as(
        r#"
        SELECT id, display_name, content_type, size_bytes, folder_id,
               is_favourite, (password_hash IS NOT NULL) AS password_protected,
               expires_at, created_at
        FROM files WHERE user_id = $1 ORDER BY created_at DESC
        "#,
    )
    .bind(user_id)
    .fetch_all(&state.db)
    .await
    .map_err(AppError::from)?;

    let names: Vec<&str> = files.iter().map(|f| f.display_name.as_str()).collect();
    let file_urls = urls::file_urls(&state.db, user_id, &names).await?;
    for (i, file) in files.iter_mut().enumerate() {
        file.url = file_urls.get(i * 2).cloned();
        file.raw_url = file_urls.get(i * 2 + 1).cloned();
    }

    Ok(files)
}

async fn fetch_pastes(state: &AppState, user_id: &str) -> Result<Vec<PasteExport>, AppError> {
    let mut pastes: Vec<PasteExport> = sqlx::query_as(
        r#"
        SELECT id, key, title, content, syntax,
               (password_hash IS NOT NULL) AS password_protected,
               expires_at, created_at
        FROM pastes WHERE user_id = $1 ORDER BY created_at DESC
        "#,
    )
    .bind(user_id)
    .fetch_all(&state.db)
    .await
    .map_err(AppError::from)?;

    let base = urls::paste_url(&state.db, user_id, "").await?;
    for paste in &mut pastes {
        paste.url = base.as_ref().map(|b| format!("{b}{}", paste.key));
    }
    Ok(pastes)
}

async fn fetch_links(state: &AppState, user_id: &str) -> Result<Vec<LinkExport>, AppError> {
    let mut links: Vec<LinkExport> = sqlx::query_as(
        r#"
        SELECT id, key, target_url, expires_at, created_at
        FROM short_links WHERE user_id = $1 ORDER BY created_at DESC
        "#,
    )
    .bind(user_id)
    .fetch_all(&state.db)
    .await
    .map_err(AppError::from)?;

    let base = urls::short_link_url(&state.db, user_id, "").await?;
    for link in &mut links {
        link.url = base.as_ref().map(|b| format!("{b}{}", link.key));
    }
    Ok(links)
}

async fn fetch_folders(state: &AppState, user_id: &str) -> Result<Vec<FolderExport>, AppError> {
    sqlx::query_as(
        r#"
        SELECT id, name, parent_id, created_at
        FROM folders WHERE user_id = $1 ORDER BY created_at ASC
        "#,
    )
    .bind(user_id)
    .fetch_all(&state.db)
    .await
    .map_err(AppError::from)
}
