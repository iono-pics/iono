use chrono::{DateTime, Utc};

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct EmbedPreset {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub site_name: Option<String>,
    pub site_url: Option<String>,
    pub author_name: Option<String>,
    pub author_url: Option<String>,
    pub title: Option<String>,
    pub description: Option<String>,
    pub color: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
