use sqlx::PgPool;
use std::sync::Arc;

use crate::config::Config;
use crate::db;
use crate::storage::{self, Storage};

pub struct CoreState {
    pub storage: Arc<dyn Storage>,
    pub db: PgPool,
}

impl CoreState {
    pub async fn build(config: &Config) -> Self {
        let storage = storage::build(config)
            .await
            .expect("failed to initialize storage backend");
        let db = db::build(config)
            .await
            .expect("failed to connect to database");
        Self { storage, db }
    }
}

pub trait HasDb {
    fn db(&self) -> &PgPool;
}

impl HasDb for CoreState {
    fn db(&self) -> &PgPool {
        &self.db
    }
}
