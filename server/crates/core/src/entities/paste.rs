use chrono::{DateTime, Utc};

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Paste {
    pub id: String,
    pub user_id: String,
    pub key: String,
    pub title: Option<String>,
    pub content: String,
    pub syntax: Option<String>,
    pub views: i64,
    pub password_hash: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}
