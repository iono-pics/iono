use sqlx::PgPool;

use crate::error::{AppError, AppResult};

pub async fn file_urls(
    db: &PgPool,
    user_id: &str,
    display_names: &[&str],
) -> AppResult<Vec<String>> {
    if display_names.is_empty() {
        return Ok(Vec::new());
    }
    let Some((host, prefix)) = resolve_domain(
        db,
        user_id,
        "SELECT d.name, ds.files_path_prefix
         FROM domain_settings ds
         INNER JOIN domains d ON d.id = ds.files_domain_id
         WHERE ds.user_id = $1",
    )
    .await?
    else {
        return Ok(Vec::new());
    };

    let mut urls = Vec::with_capacity(display_names.len() * 2);
    for name in display_names {
        urls.push(format!("https://{host}/{prefix}{name}"));
        urls.push(format!("https://{host}/{prefix}raw/{name}"));
    }
    Ok(urls)
}

pub async fn paste_url(db: &PgPool, user_id: &str, key: &str) -> AppResult<Option<String>> {
    Ok(resolve_domain(
        db,
        user_id,
        "SELECT d.name, ds.pastes_path_prefix
         FROM domain_settings ds
         INNER JOIN domains d ON d.id = ds.pastes_domain_id
         WHERE ds.user_id = $1",
    )
    .await?
    .map(|(host, prefix)| format!("https://{host}/p/{prefix}{key}")))
}

pub async fn short_link_url(db: &PgPool, user_id: &str, key: &str) -> AppResult<Option<String>> {
    Ok(resolve_domain(
        db,
        user_id,
        "SELECT d.name, ds.short_links_path_prefix
         FROM domain_settings ds
         INNER JOIN domains d ON d.id = ds.short_links_domain_id
         WHERE ds.user_id = $1",
    )
    .await?
    .map(|(host, prefix)| format!("https://{host}/l/{prefix}{key}")))
}

async fn resolve_domain(
    db: &PgPool,
    user_id: &str,
    query: &'static str,
) -> AppResult<Option<(String, String)>> {
    let row: Option<(String, Option<String>)> = sqlx::query_as(query)
        .bind(user_id)
        .fetch_optional(db)
        .await
        .map_err(AppError::from)?;

    Ok(row.map(|(host, prefix)| {
        let prefix = prefix.map(|p| format!("{p}/")).unwrap_or_default();
        (host, prefix)
    }))
}
