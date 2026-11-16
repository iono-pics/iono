use secrecy::SecretString;
use sqlx::PgPool;
use std::sync::Arc;

use crate::bootstrap::fatal;
use crate::config::Config;
use crate::db;
use crate::storage::{self, Storage};

pub struct CoreState {
    pub keyring: crate::crypto::Keyring,
    pub storage: Arc<dyn Storage>,
    pub db: PgPool,
    pub config: Config,
}

impl CoreState {
    pub async fn build(config: &Config) -> Self {
        let storage = storage::build(config)
            .await
            .unwrap_or_else(|e| fatal("initialize the storage backend", &e));
        let db = db::build(config)
            .await
            .unwrap_or_else(|e| fatal("connect to the database", &e));
        let keyring = config
            .keyring()
            .unwrap_or_else(|e| fatal("build the encryption keyring", &e));
        crate::auth::password::init_dummy_hash()
            .unwrap_or_else(|e| fatal("build the dummy password hash", &e));
        Self {
            keyring,
            storage,
            db,
            config: config.clone(),
        }
    }
}

pub trait HasDb {
    fn db(&self) -> &PgPool;
}

pub trait HasJwtSecret {
    fn jwt_secret(&self) -> &SecretString;
}

impl HasDb for CoreState {
    fn db(&self) -> &PgPool {
        &self.db
    }
}

impl HasJwtSecret for CoreState {
    fn jwt_secret(&self) -> &SecretString {
        &self.config.jwt_secret
    }
}
