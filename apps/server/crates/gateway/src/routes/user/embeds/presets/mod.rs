pub mod create;
pub mod delete;
pub mod list;
pub mod update;

use chrono::{DateTime, Utc};
use iono_core::entities::EmbedPreset;
use serde::Serialize;
use utoipa::ToSchema;

#[derive(Debug, Serialize, ToSchema)]
pub struct EmbedPresetResponse {
    id: String,
    name: String,
    site_name: Option<String>,
    site_url: Option<String>,
    author_name: Option<String>,
    author_url: Option<String>,
    title: Option<String>,
    description: Option<String>,
    color: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<EmbedPreset> for EmbedPresetResponse {
    fn from(p: EmbedPreset) -> Self {
        Self {
            id: p.id,
            name: p.name,
            site_name: p.site_name,
            site_url: p.site_url,
            author_name: p.author_name,
            author_url: p.author_url,
            title: p.title,
            description: p.description,
            color: p.color,
            created_at: p.created_at,
            updated_at: p.updated_at,
        }
    }
}
