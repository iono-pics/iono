use actix_web::{get, http::header, web, HttpResponse};
use chrono::Utc;
use iono_core::{auth::password::verify_password_async, entities::Paste, web::ApiResult, AppError};
use maud::{html, DOCTYPE};
use serde::Deserialize;

use crate::state::AppState;

#[derive(Deserialize)]
pub struct PasteQuery {
    password: Option<String>,
}

#[get("/p/{key}")]
pub async fn view_paste(
    state: web::Data<AppState>,
    path: web::Path<String>,
    query: web::Query<PasteQuery>,
) -> ApiResult<HttpResponse> {
    let paste = fetch_paste(&state, &path.into_inner()).await?;
    render_paste(paste, &query).await
}

#[get("/p/{prefix}/{key}")]
pub async fn view_paste_with_prefix(
    state: web::Data<AppState>,
    path: web::Path<(String, String)>,
    query: web::Query<PasteQuery>,
) -> ApiResult<HttpResponse> {
    let (prefix, key) = path.into_inner();
    let paste = fetch_paste_with_prefix(&state, &prefix, &key).await?;
    render_paste(paste, &query).await
}

async fn render_paste(paste: Paste, query: &PasteQuery) -> ApiResult<HttpResponse> {
    if !unlock(&paste, query.password.as_deref()).await? {
        return Err(AppError::NotFound.into());
    }

    let mut response = HttpResponse::Ok();
    response
        .content_type(header::ContentType::html())
        .append_header((header::X_CONTENT_TYPE_OPTIONS, "nosniff"))
        .append_header((header::CACHE_CONTROL, cache_control(&paste)));

    Ok(response.body(render_html(&paste)))
}

async fn fetch_paste(state: &AppState, key: &str) -> Result<Paste, AppError> {
    sqlx::query_as::<_, Paste>(
        "SELECT * FROM pastes WHERE key = $1 AND (expires_at IS NULL OR expires_at > now())",
    )
    .bind(key)
    .fetch_optional(&state.db)
    .await
    .map_err(AppError::from)?
    .ok_or(AppError::NotFound)
}

async fn fetch_paste_with_prefix(
    state: &AppState,
    prefix: &str,
    key: &str,
) -> Result<Paste, AppError> {
    sqlx::query_as::<_, Paste>(
        r#"
        SELECT p.* FROM pastes p
        INNER JOIN domain_settings ds ON ds.user_id = p.user_id
        WHERE p.key = $1
        AND ds.pastes_path_prefix = $2
        AND (p.expires_at IS NULL OR p.expires_at > now())
        "#,
    )
    .bind(key)
    .bind(prefix)
    .fetch_optional(&state.db)
    .await
    .map_err(AppError::from)?
    .ok_or(AppError::NotFound)
}

async fn unlock(paste: &Paste, password: Option<&str>) -> Result<bool, AppError> {
    let Some(hash) = paste.password_hash.clone() else {
        return Ok(true);
    };
    let Some(password) = password.map(str::to_owned) else {
        return Ok(false);
    };

    verify_password_async(password, hash).await
}

fn cache_control(paste: &Paste) -> String {
    const YEAR: i64 = 31_536_000;
    if paste.password_hash.is_some() {
        return "no-store".into();
    }
    let max_age = paste
        .expires_at
        .map(|expires| (expires - Utc::now()).num_seconds().clamp(0, YEAR))
        .unwrap_or(YEAR);
    format!("public, max-age={max_age}, immutable")
}

fn render_html(paste: &Paste) -> String {
    let title = paste.title.as_deref().unwrap_or("Paste");
    let syntax = paste.syntax.as_deref().unwrap_or("plain text");
    let created_at = paste.created_at.format("%B %-d, %Y at %H:%M UTC");

    html! {
        (DOCTYPE)
        html {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { (title) }
                meta property="og:title" content=(title);
                meta property="og:site_name" content="iono";
                meta name="theme-color" content="#7c3aed";
            }
            body {
                main {
                    header {
                        h1 { (title) }
                        p { (syntax) " / " (created_at) }
                    }
                    pre { code { (&paste.content) } }
                }
            }
        }
    }
    .into_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn escapes_paste_content_and_title() {
        let paste = Paste {
            id: "p1".into(),
            user_id: "u1".into(),
            key: "abc".into(),
            title: Some("<script>title</script>".into()),
            content: "<script>alert(1)</script>".into(),
            syntax: None,
            password_hash: None,
            expires_at: None,
            created_at: Utc::now(),
        };

        let html = render_html(&paste);
        assert!(!html.contains("<script>alert"));
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    }
}
