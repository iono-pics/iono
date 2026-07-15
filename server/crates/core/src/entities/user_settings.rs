use chrono::{DateTime, Utc};
use serde::Deserialize;
use utoipa::ToSchema;

#[derive(Debug, Clone, PartialEq, Eq, sqlx::Type, Deserialize, ToSchema)]
#[sqlx(type_name = "text", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum DisplayNameStyle {
    Normal,
    Emoji,
    Accents,
    Invisible,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserSettings {
    pub user_id: String,
    pub display_name_length: i16,
    pub display_name_style: DisplayNameStyle,
    pub display_name_include_extension: bool,
    pub raw_links_only: bool,
    pub default_expires_in_seconds: Option<i64>,
    pub lossless_images: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
