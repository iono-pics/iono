//! what has to happen after a row is gone: its object leaves storage and its
//! copies leave the edge cache. callers enqueue in the same transaction as the
//! row delete, then process right after commit. anything that fails stays in
//! pending_deletions for the janitor to retry, so nothing is orphaned and no
//! deleted file keeps being served from the edge

use sqlx::PgPool;
use std::collections::HashSet;
use uuid::Uuid;

use crate::cloudflare::CloudflareClient;
use crate::error::{AppError, AppResult};
use crate::storage::Storage;

/// the viewer tags every cacheable response with these, so one purge reaches
/// every url a resource was served under, prefixed, raw or renamed
pub fn file_tag(id: &str) -> String {
    format!("file-{id}")
}

pub fn paste_tag(id: &str) -> String {
    format!("paste-{id}")
}

pub fn user_tag(id: &str) -> String {
    format!("user-{id}")
}

#[derive(Debug, Clone, Default)]
pub struct Pending {
    pub s3_key: Option<String>,
    pub cache_tag: Option<String>,
}

impl Pending {
    pub fn file(id: &str, s3_key: impl Into<String>) -> Self {
        Self {
            s3_key: Some(s3_key.into()),
            cache_tag: Some(file_tag(id)),
        }
    }

    /// an object nobody could have fetched through the cache yet, or one whose
    /// cached copies already expired with it
    pub fn object(s3_key: impl Into<String>) -> Self {
        Self {
            s3_key: Some(s3_key.into()),
            cache_tag: None,
        }
    }

    pub fn tag(tag: String) -> Self {
        Self {
            s3_key: None,
            cache_tag: Some(tag),
        }
    }
}

pub async fn enqueue<'e, E>(db: E, items: &[Pending]) -> AppResult<Vec<String>>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    if items.is_empty() {
        return Ok(Vec::new());
    }

    let ids: Vec<String> = items.iter().map(|_| Uuid::new_v4().to_string()).collect();
    let keys: Vec<Option<String>> = items.iter().map(|i| i.s3_key.clone()).collect();
    let tags: Vec<Option<String>> = items.iter().map(|i| i.cache_tag.clone()).collect();

    sqlx::query(
        r#"
        INSERT INTO pending_deletions (id, s3_key, cache_tag)
        SELECT * FROM UNNEST($1::text[], $2::text[], $3::text[])
        "#,
    )
    .bind(&ids)
    .bind(&keys)
    .bind(&tags)
    .execute(db)
    .await
    .map_err(AppError::from)?;

    Ok(ids)
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Outcome {
    pub done: u64,
    pub failed: u64,
}

#[derive(sqlx::FromRow)]
struct Row {
    id: String,
    s3_key: Option<String>,
    cache_tag: Option<String>,
}

pub struct Deleter<'a> {
    pub db: &'a PgPool,
    pub storage: &'a dyn Storage,
    pub cloudflare: &'a CloudflareClient,
}

impl Deleter<'_> {
    /// works through the rows just enqueued, for running right after commit
    pub async fn process_ids(&self, ids: &[String]) -> AppResult<Outcome> {
        if ids.is_empty() {
            return Ok(Outcome::default());
        }
        let rows = sqlx::query_as::<_, Row>(
            "SELECT id, s3_key, cache_tag FROM pending_deletions WHERE id = ANY($1)",
        )
        .bind(ids)
        .fetch_all(self.db)
        .await?;
        self.process(rows).await
    }

    /// works through the oldest leftovers, for the janitor
    pub async fn process_backlog(&self, limit: i64) -> AppResult<Outcome> {
        let rows = sqlx::query_as::<_, Row>(
            "SELECT id, s3_key, cache_tag FROM pending_deletions ORDER BY created_at LIMIT $1",
        )
        .bind(limit)
        .fetch_all(self.db)
        .await?;
        self.process(rows).await
    }

    // both steps are idempotent, so two runs racing over one row is harmless
    async fn process(&self, rows: Vec<Row>) -> AppResult<Outcome> {
        if rows.is_empty() {
            return Ok(Outcome::default());
        }

        let mut errors: Vec<(String, String)> = Vec::new();

        let keys: Vec<String> = rows.iter().filter_map(|r| r.s3_key.clone()).collect();
        if !keys.is_empty() {
            match self.storage.delete_many(&keys).await {
                Ok(deleted) => {
                    let deleted: HashSet<String> = deleted.into_iter().collect();
                    let cleared: Vec<String> = rows
                        .iter()
                        .filter(|r| r.s3_key.as_ref().is_some_and(|k| deleted.contains(k)))
                        .map(|r| r.id.clone())
                        .collect();
                    self.clear(Step::Object, &cleared).await?;
                    for row in &rows {
                        if row.s3_key.as_ref().is_some_and(|k| !deleted.contains(k)) {
                            errors.push((row.id.clone(), "object delete failed".into()));
                        }
                    }
                }
                Err(e) => {
                    for row in rows.iter().filter(|r| r.s3_key.is_some()) {
                        errors.push((row.id.clone(), e.to_string()));
                    }
                }
            }
        }

        let tagged: Vec<&Row> = rows.iter().filter(|r| r.cache_tag.is_some()).collect();
        if !tagged.is_empty() {
            let tags: Vec<String> = tagged
                .iter()
                .filter_map(|r| r.cache_tag.clone())
                .collect::<HashSet<_>>()
                .into_iter()
                .collect();
            // purge_tags is a no-op without a zone, which is what dev wants
            match self.cloudflare.purge_tags(tags).await {
                Ok(()) => {
                    let cleared: Vec<String> = tagged.iter().map(|r| r.id.clone()).collect();
                    self.clear(Step::Cache, &cleared).await?;
                }
                Err(e) => {
                    for row in tagged {
                        errors.push((row.id.clone(), e.to_string()));
                    }
                }
            }
        }

        let done = sqlx::query(
            r#"
            DELETE FROM pending_deletions
            WHERE id = ANY($1) AND s3_key IS NULL AND cache_tag IS NULL
            "#,
        )
        .bind(rows.iter().map(|r| r.id.clone()).collect::<Vec<_>>())
        .execute(self.db)
        .await?
        .rows_affected();

        let (failed_ids, messages): (Vec<String>, Vec<String>) = errors.into_iter().unzip();
        if !failed_ids.is_empty() {
            sqlx::query(
                r#"
                UPDATE pending_deletions p
                SET attempts = attempts + 1, last_error = e.message
                FROM UNNEST($1::text[], $2::text[]) AS e(id, message)
                WHERE p.id = e.id
                "#,
            )
            .bind(&failed_ids)
            .bind(&messages)
            .execute(self.db)
            .await?;
            tracing::warn!(
                count = failed_ids.len(),
                "pending deletions will be retried"
            );
        }

        let failed = failed_ids.into_iter().collect::<HashSet<_>>().len() as u64;
        Ok(Outcome { done, failed })
    }

    async fn clear(&self, step: Step, ids: &[String]) -> AppResult<()> {
        if ids.is_empty() {
            return Ok(());
        }
        let query = match step {
            Step::Object => "UPDATE pending_deletions SET s3_key = NULL WHERE id = ANY($1)",
            Step::Cache => "UPDATE pending_deletions SET cache_tag = NULL WHERE id = ANY($1)",
        };
        sqlx::query(query).bind(ids).execute(self.db).await?;
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum Step {
    Object,
    Cache,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_are_namespaced_so_ids_cannot_collide() {
        assert_eq!(file_tag("a"), "file-a");
        assert_eq!(paste_tag("a"), "paste-a");
        assert_eq!(user_tag("a"), "user-a");
        assert_ne!(file_tag("a"), paste_tag("a"));
    }

    #[test]
    fn a_file_needs_both_its_object_and_its_cache_gone() {
        let p = Pending::file("f1", "obj.png");
        assert_eq!(p.s3_key.as_deref(), Some("obj.png"));
        assert_eq!(p.cache_tag.as_deref(), Some("file-f1"));
    }
}
