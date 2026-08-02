pub mod create;
pub mod delete;
pub mod list;
pub mod update;

use chrono::{DateTime, Utc};
use iono_core::entities::Folder;
use serde::Serialize;
use utoipa::ToSchema;

#[derive(Debug, Serialize, ToSchema)]
pub struct FolderSummary {
    id: String,
    name: String,
    parent_id: Option<String>,
    created_at: DateTime<Utc>,
}

impl From<Folder> for FolderSummary {
    fn from(folder: Folder) -> Self {
        Self {
            id: folder.id,
            name: folder.name,
            parent_id: folder.parent_id,
            created_at: folder.created_at,
        }
    }
}
