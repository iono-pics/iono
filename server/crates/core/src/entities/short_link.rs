use chrono::{DateTime, Utc};

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ShortLink {
    pub id: String,
    pub user_id: String,
    pub key: String,
    pub target_url: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}
