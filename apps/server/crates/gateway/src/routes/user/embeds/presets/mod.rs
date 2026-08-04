pub mod create;
pub mod delete;
pub mod list;
pub mod update;

use chrono::{DateTime, Utc};
use iono_core::{embed_vars, entities::EmbedPreset, validators, AppError};
use serde::Serialize;
use utoipa::ToSchema;

pub struct PresetFields<'a> {
    pub site_name: Option<&'a str>,
    pub site_url: Option<&'a str>,
    pub author_name: Option<&'a str>,
    pub author_url: Option<&'a str>,
    pub title: Option<&'a str>,
    pub description: Option<&'a str>,
    pub color: Option<&'a str>,
}

impl PresetFields<'_> {
    pub fn validate(&self) -> Result<(), AppError> {
        for (label, value, max_chars) in [
            ("site_name", self.site_name, 256),
            ("author_name", self.author_name, 256),
            ("title", self.title, 256),
            ("description", self.description, 1024),
        ] {
            let Some(value) = value else { continue };
            validators::text_length(value, max_chars, label)?;
            embed_vars::validate(value, label)?;
        }

        for url in [self.site_url, self.author_url].into_iter().flatten() {
            validators::http_url(url, 2048)?;
        }

        if let Some(color) = self.color {
            validators::hex_color(color)?;
        }

        Ok(())
    }
}

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
