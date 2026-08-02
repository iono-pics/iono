use chrono::{DateTime, Duration, Utc};
use serde::Serialize;

pub const RECOVERY_WINDOW_DAYS: i64 = 30;

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct User {
    pub id: String,
    pub username: String,
    pub email: Option<String>,
    #[serde(skip_serializing)]
    pub password_hash: Option<String>,
    pub plan_id: String,
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
    pub fn recoverable_until(&self) -> Option<DateTime<Utc>> {
        self.deleted_at
            .map(|at| at + Duration::days(RECOVERY_WINDOW_DAYS))
    }

    pub fn is_pending_deletion(&self) -> bool {
        self.recoverable_until()
            .is_some_and(|until| Utc::now() < until)
    }

    pub fn is_permanently_deleted(&self) -> bool {
        self.recoverable_until()
            .is_some_and(|until| Utc::now() >= until)
    }
}
