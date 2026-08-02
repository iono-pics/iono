use chrono::{DateTime, Utc};

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct StripeEvent {
    pub id: String,
    pub r#type: String,
    pub created_at: DateTime<Utc>,
}
