use chrono::{DateTime, Utc};

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct File {
    pub id: String,
    pub user_id: String,
    pub folder_id: Option<String>,
    pub display_name: String,
    pub original_name: String,
    pub content_type: String,
    pub size_bytes: i64,
    pub password_hash: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub is_favourite: bool,
    pub encrypted: bool,
    pub encryption_iv: Option<Vec<u8>>,
    pub user_key_iv: Option<Vec<u8>>,
    pub user_key_hash: Option<String>,
    pub encryption_key_version: Option<i16>,
    pub wrapped_dek: Option<Vec<u8>>,
    pub dek_iv: Option<Vec<u8>>,
    pub encryption_format: i16,
    pub created_at: DateTime<Utc>,
}
