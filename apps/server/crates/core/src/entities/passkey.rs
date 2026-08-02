use chrono::{DateTime, Utc};
use serde::Serialize;

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct PasskeyCredential {
    pub id: String,
    pub user_id: String,
    pub name: Option<String>,
    pub credential_id: String,
    #[serde(skip_serializing)]
    pub credential: sqlx::types::Json<webauthn_rs::prelude::Passkey>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}
