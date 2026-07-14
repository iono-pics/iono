use iono_core::storage::Storage;
use sqlx::PgPool;
use std::sync::Arc;

pub struct AppState {
    pub storage: Arc<dyn Storage>,
    pub db: PgPool,
}
