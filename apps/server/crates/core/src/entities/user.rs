use chrono::{DateTime, Duration, Utc};
use serde::Serialize;

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct User {
    pub id: String,
    pub username: String,
    pub email: Option<String>,
    #[serde(skip_serializing)]
    pub password_hash: Option<String>,
    pub plan_id: String,
    pub plan_expires_at: Option<DateTime<Utc>>,
    pub stripe_customer_id: Option<String>,
    #[serde(skip_serializing)]
    pub totp_secret: Option<String>,
    pub totp_enabled: bool,
    pub passkey_required: bool,
    #[serde(skip_serializing)]
    pub token_version: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(skip_serializing)]
    pub deleted_at: Option<DateTime<Utc>>,
}

impl User {
    pub fn recoverable_until(&self, window_days: i64) -> Option<DateTime<Utc>> {
        self.deleted_at.map(|at| at + Duration::days(window_days))
    }

    pub fn is_pending_deletion(&self, window_days: i64) -> bool {
        self.recoverable_until(window_days)
            .is_some_and(|until| Utc::now() < until)
    }

    pub fn is_permanently_deleted(&self, window_days: i64) -> bool {
        self.recoverable_until(window_days)
            .is_some_and(|until| Utc::now() >= until)
    }
}
