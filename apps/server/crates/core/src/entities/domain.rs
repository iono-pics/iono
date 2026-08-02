use chrono::{DateTime, Utc};

#[derive(Debug, Clone, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "snake_case")]
pub enum DomainStatus {
    Pending,
    Active,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "snake_case")]
pub enum DomainVisibility {
    Public,
    Private,
    InviteOnly,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Domain {
    pub id: String,
    pub owner_id: Option<String>,
    pub name: String,
    pub wildcard: bool,
    pub status: DomainStatus,
    pub visibility: DomainVisibility,
    pub cloudflare_hostname_id: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DomainInvite {
    pub domain_id: String,
    pub user_id: String,
    pub invited_by: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DomainSettings {
    pub user_id: String,
    pub files_domain_id: Option<String>,
    pub pastes_domain_id: Option<String>,
    pub short_links_domain_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub files_path_prefix: Option<String>,
    pub pastes_path_prefix: Option<String>,
    pub short_links_path_prefix: Option<String>,
}
