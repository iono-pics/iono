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

pub async fn all_public_urls_for_user(db: &PgPool, user_id: &str) -> AppResult<Vec<String>> {
    let mut urls = Vec::new();

    let file_names: Vec<String> =
        sqlx::query_scalar("SELECT display_name FROM files WHERE user_id = $1")
            .bind(user_id)
            .fetch_all(db)
            .await
            .map_err(AppError::from)?;
    let name_refs: Vec<&str> = file_names.iter().map(String::as_str).collect();
    urls.extend(file_urls(db, user_id, &name_refs).await?);

    let paste_keys: Vec<String> = sqlx::query_scalar("SELECT key FROM pastes WHERE user_id = $1")
        .bind(user_id)
        .fetch_all(db)
        .await
        .map_err(AppError::from)?;
    if !paste_keys.is_empty() {
        if let Some((host, prefix)) = resolve_domain(
            db,
            user_id,
            "SELECT d.name, ds.pastes_path_prefix
             FROM domain_settings ds
             INNER JOIN domains d ON d.id = ds.pastes_domain_id
             WHERE ds.user_id = $1",
        )
        .await?
        {
            for key in &paste_keys {
                urls.push(format!("https://{host}/p/{prefix}{key}"));
            }
        }
    }

    let link_keys: Vec<String> =
        sqlx::query_scalar("SELECT key FROM short_links WHERE user_id = $1")
            .bind(user_id)
            .fetch_all(db)
            .await
            .map_err(AppError::from)?;
    if !link_keys.is_empty() {
        if let Some((host, prefix)) = resolve_domain(
            db,
            user_id,
            "SELECT d.name, ds.short_links_path_prefix
             FROM domain_settings ds
             INNER JOIN domains d ON d.id = ds.short_links_domain_id
             WHERE ds.user_id = $1",
        )
        .await?
        {
            for key in &link_keys {
                urls.push(format!("https://{host}/l/{prefix}{key}"));
            }
        }
    }

    Ok(urls)
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
