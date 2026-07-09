use chrono::{DateTime, Utc};

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Plan {
    pub id: String,
    pub name: String,
    pub storage_quota_bytes: i64,
    pub max_upload_bytes: i64,
    pub stripe_product_id: Option<String>,
    pub stripe_price_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
